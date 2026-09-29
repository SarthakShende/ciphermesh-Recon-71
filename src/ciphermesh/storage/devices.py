"""Device keyring persistence.

The keyring is the root of trust for everything a receiver accepts. It is
persisted rather than held in memory because a PI-B that loses its keyring on
restart silently stops being able to verify anything, and the failure looks
like a radio fault rather than a missing file.

Three rules this module enforces:

* **The public key never travels with the event.** A key registered from an
  inbound packet would make signatures meaningless: an attacker signs with
  their own key and ships it alongside. Registration is therefore always an
  explicit operator or installer action, never a side effect of receiving.
* **Revocation cannot fail independently.** It is a column on the row, not a
  separate table, so there is no state in which a device is revoked but the
  revocation is missing.
* **A device's key_id is immutable.** If a known device_id re-registers with a
  different key, that is either a restore or an attack. It is rejected, and
  the caller has to explicitly revoke first. Silently replacing the key would
  let anyone who knows a device id take it over.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..constants import Role
from ..crypto import key_id
from ..errors import StorageError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

__all__ = ["DeviceRecord", "DeviceRepository"]


def _now() -> tuple[str, float]:
    instant = datetime.now(timezone.utc)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ"), instant.timestamp()


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    device_id: str
    public_key: bytes
    key_id: str
    device_name: str = ""
    role: str | None = None
    location: str | None = None
    is_local: bool = False
    first_seen: str = ""
    last_seen: str = ""
    revoked: bool = False
    revoked_at: str | None = None
    revoke_reason: str | None = None

    @property
    def public_key_b64(self) -> str:
        import base64

        return base64.b64encode(self.public_key).decode("ascii")

    @property
    def usable(self) -> bool:
        """Whether this key may verify an event right now."""
        return not self.revoked

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "role": self.role,
            "key_id": self.key_id,
            "public_key": self.public_key_b64,
            "location": self.location,
            "is_local": self.is_local,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "revoke_reason": self.revoke_reason,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> DeviceRecord:
        return cls(
            device_id=row["device_id"],
            public_key=bytes(row["public_key"]),
            key_id=row["key_id"],
            device_name=row["device_name"] or "",
            role=row["role"],
            location=row["location"],
            is_local=bool(row["is_local"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            revoked=bool(row["revoked"]),
            revoked_at=row["revoked_at"],
            revoke_reason=row["revoke_reason"],
        )


class DeviceRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # -- reads --------------------------------------------------------------

    def get(self, device_id: str) -> DeviceRecord | None:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return DeviceRecord.from_row(row) if row else None

    def get_by_key_id(self, kid: str) -> DeviceRecord | None:
        row = self._conn.execute("SELECT * FROM devices WHERE key_id = ?", (kid,)).fetchone()
        return DeviceRecord.from_row(row) if row else None

    def resolve(self, kid: str) -> DeviceRecord | None:
        """Look up a key for verification.

        Returns ``None`` for a revoked device, so a caller cannot accidentally
        verify with a key it should have rejected. This is the only lookup the
        verification pipeline uses.
        """
        record = self.get_by_key_id(kid)
        if record is None or record.revoked:
            return None
        return record

    def all(self, *, include_revoked: bool = True) -> list[DeviceRecord]:
        sql = "SELECT * FROM devices"
        if not include_revoked:
            sql += " WHERE revoked = 0"
        sql += " ORDER BY device_id"
        return [DeviceRecord.from_row(r) for r in self._conn.execute(sql)]

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0])

    def trusted_key_ids(self) -> list[str]:
        return [
            r["key_id"]
            for r in self._conn.execute("SELECT key_id FROM devices WHERE revoked = 0")
        ]

    # -- writes -------------------------------------------------------------

    def register(
        self,
        device_id: str,
        public_key: bytes,
        *,
        device_name: str = "",
        role: Role | str | None = None,
        location: str | None = None,
        is_local: bool = False,
        allow_key_change: bool = False,
    ) -> DeviceRecord:
        """Add a device to the keyring, or refresh its metadata.

        The key_id is derived here rather than accepted from the caller, so a
        typo cannot register a key under an id that will never be found.
        """
        if not device_id or not device_id.strip():
            raise StorageError("device_id must not be empty")
        if len(public_key) != 32:
            raise StorageError(f"public key must be 32 bytes, got {len(public_key)}")

        kid = key_id(public_key)
        now_text, _ = _now()
        role_text = role.value if isinstance(role, Role) else role

        existing = self.get(device_id)
        if existing is not None:
            if existing.key_id != kid and not allow_key_change:
                raise StorageError(
                    f"device {device_id} is already registered with key "
                    f"{existing.key_id}; refusing to replace it with {kid}. "
                    "If the device was legitimately re-keyed, revoke it first "
                    "with an explicit reason."
                )
            if existing.key_id != kid:
                if existing.revoked:
                    raise StorageError(
                        f"device {device_id} is revoked; unrevoke it before "
                        "re-keying so the re-key is deliberate"
                    )
                try:
                    self._conn.execute(
                        "UPDATE devices SET public_key = ?, key_id = ?, "
                        "device_name = ?, role = COALESCE(?, role), "
                        "location = COALESCE(?, location), last_seen = ? "
                        "WHERE device_id = ?",
                        (
                            public_key,
                            kid,
                            device_name,
                            role_text,
                            location,
                            now_text,
                            device_id,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise StorageError(
                        f"cannot re-key {device_id} to {kid}: that key is already "
                        "registered against another device"
                    ) from exc
                LOG.warning(
                    "device re-keyed",
                    extra={
                        "event_code": "DEVICE_REVOKED",
                        "device_id": device_id,
                        "detail": f"{existing.key_id} -> {kid}",
                    },
                )
                return self.get(device_id)  # type: ignore[return-value]

            self._conn.execute(
                "UPDATE devices SET device_name = ?, role = COALESCE(?, role), "
                "location = COALESCE(?, location), last_seen = ? WHERE device_id = ?",
                (device_name, role_text, location, now_text, device_id),
            )
            return self.get(device_id)  # type: ignore[return-value]

        self._conn.execute(
            "INSERT INTO devices (device_id, device_name, role, public_key, key_id, "
            "location, is_local, first_seen, last_seen, revoked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                device_id,
                device_name,
                role_text,
                public_key,
                kid,
                location,
                1 if is_local else 0,
                now_text,
                now_text,
            ),
        )
        LOG.info(
            "device registered",
            extra={"event_code": "SECURITY_EVENT", "device_id": device_id, "key_id": kid},
        )
        return self.get(device_id)  # type: ignore[return-value]

    def touch(self, device_id: str) -> None:
        """Update last_seen without touching the key."""
        now_text, _ = _now()
        self._conn.execute(
            "UPDATE devices SET last_seen = ? WHERE device_id = ?", (now_text, device_id)
        )

    def revoke(self, device_id: str, reason: str) -> bool:
        """Revoke a device. Returns False if it was already revoked."""
        now_text, _ = _now()
        cursor = self._conn.execute(
            "UPDATE devices SET revoked = 1, revoked_at = ?, revoke_reason = ? "
            "WHERE device_id = ? AND revoked = 0",
            (now_text, reason, device_id),
        )
        if cursor.rowcount:
            LOG.warning(
                "device revoked",
                extra={
                    "event_code": "DEVICE_REVOKED",
                    "device_id": device_id,
                    "detail": reason,
                },
            )
            return True
        return False

    def unrevoke(self, device_id: str) -> bool:
        cursor = self._conn.execute(
            "UPDATE devices SET revoked = 0, revoked_at = NULL, revoke_reason = NULL "
            "WHERE device_id = ? AND revoked = 1",
            (device_id,),
        )
        return bool(cursor.rowcount)

    def delete(self, device_id: str) -> bool:
        """Remove a device entirely.

        Refused while events reference it, because deleting a keyring entry
        would orphan the history that was verified with it. Revoke instead.
        """
        try:
            cursor = self._conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        except sqlite3.IntegrityError as exc:
            raise StorageError(
                f"cannot delete device {device_id}: it still has events. Revoke it "
                "instead, which preserves the audit trail."
            ) from exc
        return bool(cursor.rowcount)

    # -- keyring projection -------------------------------------------------

    def keystore(self):
        """A :class:`~ciphermesh.crypto.KeyStore` built from the keyring.

        Rebuilt per call rather than cached. A cached keyring would let a
        revocation take effect at the next reload instead of immediately, and
        a stale keyring that still accepts a revoked device is exactly the
        failure this whole subsystem exists to prevent.
        """
        from ..crypto import KeyStore

        keys: dict[str, bytes] = {}
        revoked: set[str] = set()
        for record in self.all():
            if record.revoked:
                revoked.add(record.key_id)
            else:
                keys[record.key_id] = record.public_key
        return KeyStore(keys, frozenset(revoked))
