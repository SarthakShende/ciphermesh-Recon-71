"""Two-node round trip: PI-A originates, PI-B verifies.

PI-A and PI-B are separate processes in production with separate state
directories and separate keys. Reproducing that here - two state dirs, two
identities, no shared objects - is the only way to catch a design mistake
that would work in a single-process test and fail over the air.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ciphermesh.config.schema import EventConfig
from ciphermesh.constants import EventType, Role, Unit
from ciphermesh.crypto import KeyStore
from ciphermesh.events import Event, EventFactory, SequenceAllocator, SignedEvent
from ciphermesh.identity import IdentityManager

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def pi_b_keyring(state_dir, tmp_path):
    """Build PI-B's keyring from PI-A's published public key export.

    The key is transported the way it would be in the field: as the ``.pub``
    file, not as a shared Python object.
    """
    pi_a = IdentityManager.open(
        PASSPHRASE,
        device_id="PI-A-0001",
        device_name="greenhouse",
        role=Role.GATEWAY_SENSOR,
        identity_path=tmp_path / "pi-a" / "identity" / "device_identity.json",
    )
    exported = pi_a.public_key_path.read_text(encoding="utf-8")
    fields = dict(
        line.split(None, 1) for line in exported.splitlines() if line and not line.startswith("#")
    )
    import base64

    raw = base64.b64decode(fields["public_key"])
    return KeyStore({fields["key_id"]: raw}), pi_a


def test_pi_b_verifies_a_pi_a_event(state_dir, pi_b_keyring):
    keystore, pi_a = pi_b_keyring
    factory = EventFactory.from_identity(
        EventConfig(), pi_a, SequenceAllocator(tmp_path_seq(state_dir))
    )
    signed = factory.create(EventType.TEMPERATURE, 27.5)

    # Everything crosses as bytes, exactly as the wire encoder will do it.
    packet = signed.to_wire_dict()
    received = SignedEvent.from_wire(packet, signed.signature, signed.key_id)

    assert received.verify_with(keystore)
    assert received.event.device_id == "PI-A-0001"
    assert received.event.device_name == "greenhouse"
    assert received.recompute_hash() == received.event.hash()


def test_pi_b_rejects_an_event_signed_by_a_stranger(state_dir, tmp_path, pi_b_keyring):
    """The attack the whole trust model exists to stop."""
    keystore, _ = pi_b_keyring
    stranger = IdentityManager.open(
        "a different passphrase",
        device_id="EVIL-0001",
        role=Role.GATEWAY_SENSOR,
        identity_path=tmp_path / "evil" / "identity" / "device_identity.json",
    )
    factory = EventFactory.from_identity(
        EventConfig(), stranger, SequenceAllocator(tmp_path_seq(state_dir) / "evil.json")
    )
    signed = factory.create(EventType.TEMPERATURE, 99.9)
    # The stranger even claims to be PI-A by rewriting the device id, and
    # points the key id at the real PI-A key so the receiver looks it up.
    forged = Event(
        event_id=signed.event.event_id,
        device_id="PI-A-0001",
        event_type=signed.event.event_type,
        value=99.9,
        unit=signed.event.unit,
        sequence=signed.event.sequence,
        timestamp=signed.event.timestamp,
    )
    packet = SignedEvent(
        event=forged,
        signature=signed.signature,
        key_id=next(iter(keystore.keys)),
    )
    assert not packet.verify_with(keystore)


def test_the_public_key_never_travels(state_dir, pi_b_keyring):
    """Keys are resolved by id, never shipped in the message."""
    _, pi_a = pi_b_keyring
    factory = EventFactory.from_identity(
        EventConfig(), pi_a, SequenceAllocator(tmp_path_seq(state_dir))
    )
    packet = factory.create(EventType.TEMPERATURE, 27.5).to_wire_dict()
    assert "public_key" not in packet
    assert "key_id" not in packet


def test_a_restarted_pi_a_never_reuses_a_sequence(state_dir, tmp_path):
    """Two process lifetimes, one state directory: the counter must not rewind."""
    seq_path = tmp_path_seq(state_dir)
    identity = IdentityManager.open(
        PASSPHRASE,
        device_id="PI-A-0001",
        role=Role.GATEWAY_SENSOR,
        identity_path=tmp_path / "pi-a" / "identity" / "device_identity.json",
    )
    config = EventConfig()

    first_run = EventFactory.from_identity(config, identity, SequenceAllocator(seq_path))
    first = [first_run.create(EventType.TEMPERATURE, 20.0 + i).event.sequence for i in range(5)]

    # "Restart": brand new manager, brand new allocator, same state directory.
    restarted_identity = IdentityManager.open(
        PASSPHRASE,
        device_id="PI-A-0001",
        role=Role.GATEWAY_SENSOR,
        identity_path=tmp_path / "pi-a" / "identity" / "device_identity.json",
    )
    second_run = EventFactory.from_identity(config, restarted_identity, SequenceAllocator(seq_path))
    second = [second_run.create(EventType.TEMPERATURE, 25.0 + i).event.sequence for i in range(5)]

    assert first == [1, 2, 3, 4, 5]
    assert second == [6, 7, 8, 9, 10]
    assert not set(first) & set(second)


def test_a_restored_database_does_not_get_renumbered(state_dir, tmp_path):
    """A backup of the database newer than the counter file."""
    identity = IdentityManager.open(
        PASSPHRASE,
        device_id="PI-A-0001",
        role=Role.GATEWAY_SENSOR,
        identity_path=tmp_path / "pi-a" / "identity" / "device_identity.json",
    )
    seq_path = tmp_path_seq(state_dir)
    EventFactory.from_identity(EventConfig(), identity, SequenceAllocator(seq_path)).create(
        EventType.TEMPERATURE, 20.0
    )

    # The database says 40 events already exist; the counter file says 1.
    healed = SequenceAllocator(seq_path, max_hint=lambda: 40)
    factory = EventFactory.from_identity(EventConfig(), identity, healed)
    assert factory.create(EventType.TEMPERATURE, 20.0).event.sequence == 41


def test_state_directories_are_isolated_from_each_other(tmp_path, monkeypatch):
    """Two nodes on one host must not read each other's identity."""
    a_state = tmp_path / "a"
    b_state = tmp_path / "b"
    keys = []
    for name, root in (("PI-A-0001", a_state), ("PI-B-0001", b_state)):
        (root / "identity").mkdir(parents=True)
        os.chmod(root / "identity", 0o700)
        identity = IdentityManager.open(
            PASSPHRASE, device_id=name, identity_path=root / "identity" / "device_identity.json"
        )
        keys.append(identity.key_id)
    assert keys[0] != keys[1]


def test_a_humidity_reading_is_its_own_signed_event(state_dir, pi_b_keyring):
    keystore, pi_a = pi_b_keyring
    factory = EventFactory.from_identity(
        EventConfig(), pi_a, SequenceAllocator(tmp_path_seq(state_dir))
    )
    events = factory.create_reading(27.5, humidity=61.25)
    assert [e.event.sequence for e in events] == [1, 2]
    for signed in events:
        assert signed.verify_with(keystore)
    assert events[1].event.unit is Unit.PERCENT_RH


def tmp_path_seq(state_dir) -> Path:
    return Path(state_dir) / "sequence.json"
