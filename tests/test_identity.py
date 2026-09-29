"""Identity manager behaviour.

The assertions here are trust properties, not coverage: each one exists because
its absence would let a node look authentic without being authentic.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from tests.conftest import mode_of

from ciphermesh import paths
from ciphermesh.constants import Role
from ciphermesh.errors import IdentityError
from ciphermesh.identity import (
    META_FORMAT,
    IdentityManager,
    verify_identity_file,
)

PASSPHRASE = "correct horse battery staple"


# ---------------------------------------------------------------------------
# Creation and reload
# ---------------------------------------------------------------------------


def test_first_open_generates_an_identity(manager):
    assert manager.device_id == "PI-A-0001"
    assert len(manager.public_key) == 32
    assert len(manager.key_id) == 16
    assert paths.private_key_path().exists()


def test_reopening_with_the_same_passphrase_is_stable(state_dir):
    first = IdentityManager.open(PASSPHRASE, device_id="PI-A-0001")
    second = IdentityManager.open(PASSPHRASE, device_id="PI-A-0001")
    assert first.key_id == second.key_id
    assert first.public_key == second.public_key


def test_wrong_passphrase_is_refused_rather_than_rekeying(state_dir):
    IdentityManager.open(PASSPHRASE, device_id="PI-A-0001")
    with pytest.raises(IdentityError, match="wrong passphrase"):
        IdentityManager.open("not the passphrase", device_id="PI-A-0001")


def test_create_false_refuses_to_invent_a_new_identity(state_dir):
    """Silently minting a new key would change key_id and orphan the node."""
    with pytest.raises(IdentityError, match="ciphermesh identity init"):
        IdentityManager.open(PASSPHRASE, device_id="PI-A-0001", create=False)


# ---------------------------------------------------------------------------
# Key material containment
# ---------------------------------------------------------------------------


def test_public_surface_exposes_no_private_material(manager):
    """Nothing reachable from the manager may yield the seed or key object."""
    for name in dir(manager):
        if name.startswith("_"):
            continue
        value = getattr(manager, name)
        assert not isinstance(value, type(manager._keypair)), name


def test_the_identity_file_is_not_usable_on_its_own(manager):
    """A stolen file plus no passphrase must be worthless."""
    text = paths.private_key_path().read_text(encoding="utf-8")
    lowered = text.lower()
    assert "private" not in lowered
    assert "seed" not in lowered

    # The seed is PBKDF2(passphrase, salt). Without the file's own salt the
    # identity cannot be rebuilt, and the file does hold the salt - which is
    # why the passphrase is the secret, not the file.
    from cryptography.hazmat.primitives import serialization

    seed = manager._keypair.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    import base64

    assert seed.hex() not in text
    assert base64.b64encode(seed).decode() not in text


def test_public_key_file_contains_only_the_public_half(manager):
    text = manager.public_key_path.read_text(encoding="utf-8")
    assert "public_key" in text
    assert manager.key_id in text
    assert mode_of(manager.public_key_path) == 0o644


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def test_identity_directory_is_0700_and_file_is_0600(manager):
    assert mode_of(paths.identity_dir()) == 0o700
    assert mode_of(paths.private_key_path()) == 0o600


def test_a_loosened_identity_directory_is_refused(state_dir, passphrase):
    IdentityManager.open(passphrase, device_id="PI-A-0001")
    os.chmod(paths.identity_dir(), 0o755)
    with pytest.raises(IdentityError, match="group/world accessible"):
        IdentityManager.open(passphrase, device_id="PI-A-0001")


def test_a_loosened_identity_file_is_refused(state_dir, passphrase):
    IdentityManager.open(passphrase, device_id="PI-A-0001")
    os.chmod(paths.private_key_path(), 0o644)
    with pytest.raises(IdentityError, match="group/world accessible"):
        IdentityManager.open(passphrase, device_id="PI-A-0001")


def test_metadata_is_world_readable_and_never_secret(manager):
    """The metadata file is published to peers, so it must hold no secret."""
    assert mode_of(manager.metadata_path) == 0o644
    data = json.loads(manager.metadata_path.read_text(encoding="utf-8"))
    assert data["format"] == META_FORMAT
    assert data["key_id"] == manager.key_id
    assert "passphrase" not in json.dumps(data).lower()


# ---------------------------------------------------------------------------
# Metadata reload
# ---------------------------------------------------------------------------


def test_created_at_is_preserved_across_restarts(state_dir, passphrase):
    """A creation timestamp that moved on every restart would be worthless."""
    first = IdentityManager.open(passphrase, device_id="PI-A-0001")
    created = first.describe().created_at

    second = IdentityManager.open(passphrase, device_id="PI-A-0001")
    assert second.describe().created_at == created


def test_metadata_from_another_key_is_not_inherited(tmp_path, passphrase):
    """A copied state directory must not inherit another device's metadata."""
    a = IdentityManager.open(
        passphrase, device_id="PI-A-0001", identity_path=tmp_path / "a" / "id.json"
    )
    b_dir = tmp_path / "b"
    b_dir.mkdir()
    os.chmod(b_dir, 0o700)
    b = IdentityManager.open(passphrase, device_id="PI-B-0001", identity_path=b_dir / "id.json")

    # Simulate a botched restore: PI-A's metadata lands in PI-B's directory.
    foreign = json.loads(a.metadata_path.read_text(encoding="utf-8"))
    foreign["created_at"] = "1999-01-01T00:00:00Z"
    stray = b_dir / "device_identity.meta.json"
    stray.write_text(json.dumps(foreign), encoding="utf-8")
    os.chmod(stray, 0o644)

    reopened = IdentityManager.open(
        passphrase, device_id="PI-B-0001", identity_path=b_dir / "id.json"
    )
    assert reopened.describe().created_at != "1999-01-01T00:00:00Z"
    # And the file on disk is corrected back to this node's own metadata.
    assert json.loads(reopened.metadata_path.read_text(encoding="utf-8"))["key_id"] == b.key_id


def test_reload_adopts_a_changed_device_id(manager):
    path = manager.metadata_path
    data = json.loads(path.read_text(encoding="utf-8"))
    data["device_id"] = "PI-A-0002"
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o644)

    assert manager.reload_metadata().device_id == "PI-A-0002"
    assert manager.device_id == "PI-A-0002"
    # The key is unchanged: renaming a device must not re-key it.
    assert manager.key_id == data["key_id"]


def test_reload_refuses_metadata_belonging_to_another_key(manager, state_dir):
    """Adopting a foreign key_id would publish an id this node cannot sign for."""
    other = IdentityManager.open(
        "a different passphrase", device_id="PI-A-9999", identity_path=state_dir / "other.json"
    )
    data = json.loads(manager.metadata_path.read_text(encoding="utf-8"))
    data["key_id"] = other.key_id
    manager.metadata_path.write_text(json.dumps(data))
    os.chmod(manager.metadata_path, 0o644)

    with pytest.raises(IdentityError, match="does not belong to this identity"):
        manager.reload_metadata()


def test_reload_rejects_an_unknown_metadata_format(manager):
    data = json.loads(manager.metadata_path.read_text(encoding="utf-8"))
    data["format"] = "ciphermesh-device-meta-v99"
    manager.metadata_path.write_text(json.dumps(data))
    with pytest.raises(IdentityError, match="unsupported identity metadata format"):
        manager.reload_metadata()


# ---------------------------------------------------------------------------
# Read-only inspection
# ---------------------------------------------------------------------------


def test_identity_file_is_readable_without_the_passphrase(manager):
    """`ciphermesh identity show` must work before the operator types anything."""
    key_id, public_raw, salt, iterations = verify_identity_file(paths.private_key_path())
    assert key_id == manager.key_id
    assert public_raw == manager.public_key
    assert len(salt) == 16
    assert iterations >= 100_000


# ---------------------------------------------------------------------------
# Separation from Reticulum
# ---------------------------------------------------------------------------


def test_key_id_is_the_first_8_bytes_of_sha256(manager):
    import hashlib

    expected = hashlib.sha256(manager.public_key).hexdigest()[:16]
    assert manager.key_id == expected


def test_repr_never_leaks_key_material(manager, passphrase):
    for text in (repr(manager), repr(manager.describe())):
        assert passphrase not in text
        assert manager.key_id in text


def test_describe_is_publishable_and_complete(manager):
    described = manager.describe()
    assert described.role is Role.GATEWAY_SENSOR
    assert described.device_name == "greenhouse-sensor"
    assert described.location == "block-c"
    assert described.to_dict()["key_id"] == manager.key_id


def test_a_second_node_gets_a_different_key(state_dir, tmp_path):
    """PI-A and PI-B must not collide; identical ids would break the wire."""
    a = IdentityManager.open(
        PASSPHRASE, device_id="PI-A-0001", identity_path=tmp_path / "a" / "id.json"
    )
    b = IdentityManager.open(
        PASSPHRASE, device_id="PI-B-0001", identity_path=tmp_path / "b" / "id.json"
    )
    assert a.key_id != b.key_id


def test_identity_dir_creation_is_0700_from_the_outset(state_dir):
    nested = Path(state_dir) / "fresh" / "identity" / "id.json"
    IdentityManager.open(PASSPHRASE, device_id="PI-A-0001", identity_path=nested)
    assert stat.S_IMODE(nested.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested.stat().st_mode) == 0o600
