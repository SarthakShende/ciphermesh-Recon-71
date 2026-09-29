"""Device identity manager.

This is the only module that owns the node's Ed25519 key material. It exists
so that no other part of ciphermesh has to know *where* keys live, *how* they
are protected, or what happens if the passphrase is wrong.

Two properties are enforced here and are covered by tests:

1. **The key material never leaves this object.** :attr:`IdentityManager._keypair`
   is private and only exposed through :meth:`sign`, which returns a signature
   over bytes the caller supplies. No accessor returns the seed or the private
   key object, so no caller can log it by accident.
2. **These keys are CipherMesh's, not Reticulum's.** Reticulum maintains its
   own identity in its own storage directory, and PI-A and PI-B are expected
   to run distinct Reticulum instances (``share_instance: No``). Reusing one
   key for both layers would let a Reticulum-level signature be replayed as a
   CipherMesh event signature, which is exactly the cross-protocol replay the
   ``CIPHERMESH-EVENT-v1`` domain separator exists to prevent. A compromise of
   the Reticulum layer therefore does not yield the ability to forge events.

The on-disk format is written by :mod:`ciphermesh.crypto.signing`: the seed is
derived from a passphrase with PBKDF2-HMAC-SHA256, so the identity file holds
no usable secret on its own.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import paths
from .constants import Role
from .crypto import KeyPair
from .crypto.signing import (
    IDENTITY_FORMAT,
    SALT_BYTES,
    load_or_create_identity,
    read_identity,
)
from .errors import IdentityError
from .logging_setup import get_logger

LOG = get_logger(__name__)

#: Bumped if the metadata file layout changes. Older files are migrated by
#: rewriting them, never by guessing.
META_FORMAT = "ciphermesh-device-meta-v1"

__all__ = [
    "META_FORMAT",
    "DeviceIdentity",
    "IdentityManager",
    "load_identity_manager",
]


# ---------------------------------------------------------------------------
# Immutable view handed to the rest of the application
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Everything about this node that is safe to publish.

    Deliberately holds no private material, so it is safe to pass to the API,
    the cloud client, or a log call.
    """

    device_id: str
    device_name: str
    role: Role
    key_id: str
    public_key: bytes
    created_at: str
    location: str | None = None

    @property
    def public_key_b64(self) -> str:
        import base64

        return base64.b64encode(self.public_key).decode("ascii")

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "role": self.role.value,
            "key_id": self.key_id,
            "public_key": self.public_key_b64,
            "created_at": self.created_at,
            "location": self.location,
        }

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"DeviceIdentity(device_id={self.device_id!r}, key_id={self.key_id!r})"


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class IdentityManager:
    """Owns the node key pair and the public metadata around it.

    Thread-safe: :meth:`sign` is called from the sensor thread and the CLI may
    call :meth:`describe` concurrently. The lock is only ever held around a
    dict read or a file write, never across a signature computation.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        keypair: KeyPair,
        *,
        identity_path: Path | None = None,
    ) -> None:
        self._identity = identity
        self._keypair = keypair
        # Metadata is written next to the identity file it describes, never to
        # a location derived from the environment. Otherwise pointing a test
        # (or a second instance) at one directory would still write metadata
        # into the node's real state directory.
        anchor = Path(identity_path).parent if identity_path else paths.identity_dir()
        self._identity_path = Path(identity_path) if identity_path else paths.private_key_path()
        self._meta_path = anchor / paths.IDENTITY_META_FILENAME
        self._public_path = anchor / paths.PUBLIC_KEY_FILENAME
        self._lock = threading.Lock()

    # -- construction -------------------------------------------------------

    @classmethod
    def open(
        cls,
        passphrase: str,
        *,
        device_id: str,
        device_name: str = "",
        role: Role = Role.GATEWAY_SENSOR,
        location: str | None = None,
        identity_path: Path | None = None,
        create: bool = True,
    ) -> IdentityManager:
        """Load the node identity, creating it on first run.

        With ``create=False`` a missing identity is an error rather than a new
        key. That is what the service and ``ciphermesh start`` use: silently
        minting a fresh identity because a file went missing would change this
        node's ``key_id`` and every peer would start reporting UNKNOWN_DEVICE.
        """
        path = Path(identity_path) if identity_path else paths.private_key_path()

        if not path.exists() and not create:
            raise IdentityError(
                f"no identity at {path}; run 'ciphermesh identity init' first"
            )

        existed = path.exists()
        # The salt is only consumed on creation; on load it comes from the file.
        import secrets

        keypair = load_or_create_identity(path, passphrase, salt=secrets.token_bytes(SALT_BYTES))

        cls._assert_permissions(path)

        identity = DeviceIdentity(
            device_id=device_id,
            device_name=device_name or device_id,
            role=role,
            key_id=keypair.key_id,
            public_key=keypair.public_raw,
            # Preserved across restarts. A field called created_at that changes
            # every time the service restarts is worse than no field at all.
            created_at=_existing_created_at(path, keypair.key_id) or _now_iso(),
            location=location,
        )
        manager = cls(identity, keypair, identity_path=path)
        manager._write_metadata()

        LOG.log(
            30 if existed else 40,
            "identity %s",
            "loaded" if existed else "generated",
            extra={
                "event_code": "IDENTITY_LOADED" if existed else "IDENTITY_GENERATED",
                "device_id": device_id,
                "key_id": keypair.key_id,
                "path": str(path),
            },
        )
        return manager

    # -- public surface -----------------------------------------------------

    @property
    def key_id(self) -> str:
        """8-byte SHA-256 prefix of the public key, in wire hex form."""
        return self._identity.key_id

    @property
    def device_id(self) -> str:
        return self._identity.device_id

    @property
    def public_key(self) -> bytes:
        """Raw 32-byte Ed25519 public key. Public by definition."""
        return self._identity.public_key

    def describe(self) -> DeviceIdentity:
        """The publishable view of this node's identity."""
        return self._identity

    def sign(self, message: bytes) -> bytes:
        """Sign arbitrary bytes. The only way to use the private key."""
        return self._keypair.sign(message)

    def sign_event(self, payload: Any) -> bytes:
        """Sign a canonical event payload, with the event domain separator."""
        return self._keypair.sign_event(payload)

    def verify_own_signature(self, signature: bytes, payload: Any) -> bool:
        """Self-check used after generation to fail loudly on a broken stack."""
        from .crypto import verify_event

        return verify_event(self.public_key, signature, payload)

    # -- permission hygiene -------------------------------------------------

    @staticmethod
    def _assert_permissions(path: Path) -> None:
        """Log a directory that is *stricter* than required.

        Loosening is already fatal: :func:`ciphermesh.crypto.signing.read_identity`
        refuses a group/world-accessible identity file or directory, so this
        never has to decide what to do about it. What it does have to catch is
        a directory left at e.g. 0500 by a restore, which is safe but stops the
        node writing its own metadata.
        """
        parent = path.parent
        try:
            dir_mode = stat.S_IMODE(parent.stat().st_mode)
        except FileNotFoundError:  # pragma: no cover - written moments ago
            return
        if not dir_mode & 0o077 and dir_mode != paths.DIR_MODE:
            os.chmod(parent, paths.DIR_MODE)
            LOG.warning(
                "restored write access to the identity directory",
                extra={
                    "event_code": "KEY_PERMISSION_FIXED",
                    "path": str(parent),
                    "was": oct(dir_mode),
                    "now": oct(paths.DIR_MODE),
                },
            )

    # -- metadata -----------------------------------------------------------

    def _write_metadata(self) -> None:
        """Write the public metadata file and the ``.pub`` export.

        Both are written atomically and at 0644 because they contain nothing
        secret; the identity file next to them stays at 0600.
        """
        self._meta_path.parent.mkdir(parents=True, exist_ok=True, mode=paths.DIR_MODE)

        payload = {
            "format": META_FORMAT,
            "identity_format": IDENTITY_FORMAT,
            **self._identity.to_dict(),
        }
        _write_json_atomic(self._meta_path, payload, mode=paths.PUBLIC_FILE_MODE)
        _write_text_atomic(
            self._public_path,
            f"# ciphermesh device {self._identity.device_id}\n"
            f"key_id {self._identity.key_id}\n"
            f"public_key {self._identity.public_key_b64}\n",
            mode=paths.PUBLIC_FILE_MODE,
        )

    @property
    def metadata_path(self) -> Path:
        return self._meta_path

    @property
    def public_key_path(self) -> Path:
        return self._public_path

    def reload_metadata(self) -> DeviceIdentity:
        """Re-read the public metadata file and adopt it.

        Used after ``ciphermesh identity set-device-id`` rewrites the file, so
        the running manager and the on-disk metadata cannot disagree.
        """
        path = self._meta_path
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise IdentityError(f"cannot read identity metadata {path}: {exc}") from exc

        if data.get("format") != META_FORMAT:
            raise IdentityError(
                f"unsupported identity metadata format {data.get('format')!r} in {path}"
            )
        stored_key_id = data.get("key_id")
        if stored_key_id != self._identity.key_id:
            # The metadata describes a different key than the one this process
            # holds. Adopting it would make this node sign with a key that no
            # peer trusts, or worse, publish a key id that does not match the
            # signature. Refuse.
            raise IdentityError(
                f"identity metadata {path} names key {stored_key_id} but this node "
                f"holds {self._identity.key_id}. The metadata does not belong to "
                f"this identity file."
            )

        with self._lock:
            self._identity = DeviceIdentity(
                device_id=str(data.get("device_id") or self._identity.device_id),
                device_name=str(data.get("device_name") or self._identity.device_name),
                role=_coerce_role(data.get("role"), self._identity.role),
                key_id=self._identity.key_id,
                public_key=self._identity.public_key,
                created_at=str(data.get("created_at") or self._identity.created_at),
                location=data.get("location"),
            )
        return self._identity

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"IdentityManager(device_id={self._identity.device_id!r}, "
            f"key_id={self._identity.key_id!r})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _existing_created_at(identity_path: Path, expected_key_id: str) -> str | None:
    """Recover ``created_at`` from the metadata of the *same* identity.

    A metadata file naming a different key belongs to a different node and is
    ignored rather than trusted, so a copied state directory cannot inherit
    another device's creation date.
    """
    meta = Path(identity_path).parent / paths.IDENTITY_META_FILENAME
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("format") != META_FORMAT or data.get("key_id") != expected_key_id:
        return None
    created = data.get("created_at")
    return created if isinstance(created, str) and created else None


def _coerce_role(value: Any, fallback: Role) -> Role:
    if value is None:
        return fallback
    if isinstance(value, Role):
        return value
    try:
        return Role(str(value))
    except ValueError:
        return fallback


def _write_json_atomic(path: Path, payload: dict[str, Any], *, mode: int) -> None:
    _write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=mode)


def _write_text_atomic(path: Path, text: str, *, mode: int) -> None:
    """Write via a temp file and ``os.replace`` so a crash cannot truncate."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - not all filesystems support this
        pass
    finally:
        os.close(dir_fd)


def verify_identity_file(identity_path: Path) -> tuple[str, bytes, bytes, int]:
    """Parse an identity file without needing its passphrase.

    Returns ``(key_id, public_raw, salt, iterations)``. Used by
    ``ciphermesh identity show`` and the installer, which need to display the
    key id of an existing node before they know the passphrase.
    """
    return read_identity(Path(identity_path))


def load_identity_manager(
    passphrase: str,
    config: Any = None,
    *,
    create: bool = True,
) -> IdentityManager:
    """Build an :class:`IdentityManager` from a loaded :class:`~ciphermesh.config.Config`."""
    if config is None:
        raise IdentityError("load_identity_manager requires a configuration")
    return IdentityManager.open(
        passphrase,
        device_id=config.device.id,
        device_name=config.device.name,
        role=config.device.role,
        location=config.device.location,
        create=create,
    )
