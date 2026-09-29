"""Security audit trail, replay window, and key/value state.

Three small stores that share a file. They are grouped because none of them
carries business logic, and splitting them into three modules would be three
directories for three dozen lines.

The replay window is the one with a security property worth stating: it is
consulted on the receive path to reject an event this node has already
accepted, which is a different check from the monotonic sequence test. A
sender that replays an event at a *new* sequence defeats the sequence check
but is still caught here, because the hash is identical.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..constants import SecurityEventCode
from ..errors import StorageError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

SEVERITY_INFO = "INFO"
SEVERITY_WARN = "WARN"
SEVERITY_CRITICAL = "CRITICAL"

#: Known state keys. The set is closed, and both read and write refuse anything
#: outside it, because a typo in a load-bearing key name would otherwise read as
#: "not set yet" and silently reset a security parameter.
STATE_SEQUENCE = "highest_sequence"
STATE_BOOTSTRAP = "schema_initialised"
STATE_LAST_SYNC = "last_successful_sync"
STATE_CLOUD_ETAG = "cloud_etag"
STATE_REGISTRATION = "registration_state"

STATE_KEYS = frozenset(
    {
        STATE_SEQUENCE,
        STATE_BOOTSTRAP,
        STATE_LAST_SYNC,
        STATE_CLOUD_ETAG,
        STATE_REGISTRATION,
    }
)


def _check_key(key: str) -> str:
    if key not in STATE_KEYS:
        raise StorageError(
            f"unknown system_state key {key!r}; expected one of "
            f"{sorted(STATE_KEYS)}. Use KVRepository for scratch state."
        )
    return key

__all__ = [
    "SEVERITY_CRITICAL",
    "SEVERITY_INFO",
    "SEVERITY_WARN",
    "STATE_BOOTSTRAP",
    "STATE_CLOUD_ETAG",
    "STATE_KEYS",
    "STATE_LAST_SYNC",
    "STATE_REGISTRATION",
    "STATE_SEQUENCE",
    "KVRepository",
    "ReplayWindow",
    "SecurityEventRepository",
    "SecurityRecord",
    "StateRepository",
]


def _now() -> tuple[str, float]:
    instant = datetime.now(timezone.utc)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ"), instant.timestamp()


# ---------------------------------------------------------------------------
# Security events
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecurityRecord:
    id: int
    code: str
    severity: str
    device_id: str | None
    event_id: str | None
    detail: str | None
    remote_address: str | None
    occurred_at: str
    occurred_unix: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "code": self.code,
            "severity": self.severity,
            "device_id": self.device_id,
            "event_id": self.event_id,
            "detail": self.detail,
            "remote_address": self.remote_address,
            "occurred_at": self.occurred_at,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> SecurityRecord:
        return cls(
            id=int(row["id"]),
            code=row["code"],
            severity=row["severity"],
            device_id=row["device_id"],
            event_id=row["event_id"],
            detail=row["detail"],
            remote_address=row["remote_address"],
            occurred_at=row["occurred_at"],
            occurred_unix=float(row["occurred_unix"]),
        )


class SecurityEventRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def record(
        self,
        code: SecurityEventCode | str,
        *,
        severity: str = SEVERITY_WARN,
        device_id: str | None = None,
        event_id: str | None = None,
        detail: str | None = None,
        remote_address: str | None = None,
    ) -> int:
        code_value = code.value if isinstance(code, SecurityEventCode) else str(code)
        occurred_at, occurred_unix = _now()
        cursor = self._conn.execute(
            "INSERT INTO security_events (code, severity, device_id, event_id, detail, "
            "remote_address, occurred_at, occurred_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                code_value,
                severity,
                device_id,
                event_id,
                detail,
                remote_address,
                occurred_at,
                occurred_unix,
            ),
        )
        return int(cursor.lastrowid or 0)

    def recent(
        self, *, limit: int = 100, min_severity: str | None = None
    ) -> list[SecurityRecord]:
        sql = "SELECT * FROM security_events"
        params: list[Any] = []
        if min_severity:
            order = [SEVERITY_INFO, SEVERITY_WARN, SEVERITY_CRITICAL]
            if min_severity not in order:
                raise StorageError(f"unknown severity {min_severity!r}")
            # "At least this severe", so the floor and everything above it.
            allowed = order[order.index(min_severity) :]
            sql += " WHERE severity IN (" + ",".join("?" * len(allowed)) + ")"
            params.extend(allowed)
        sql += " ORDER BY occurred_unix DESC, id DESC LIMIT ?"
        params.append(limit)
        return [SecurityRecord.from_row(r) for r in self._conn.execute(sql, params)]

    def for_event(self, event_id: str) -> list[SecurityRecord]:
        rows = self._conn.execute(
            "SELECT * FROM security_events WHERE event_id = ? ORDER BY occurred_unix",
            (event_id,),
        )
        return [SecurityRecord.from_row(r) for r in rows]

    def counts_by_code(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT code, COUNT(*) AS n FROM security_events GROUP BY code ORDER BY n DESC"
        )
        return {r["code"]: int(r["n"]) for r in rows}

    def count_since(self, code: SecurityEventCode | str, since_unix: float) -> int:
        """Count of a given code in a window - the basis of rate limiting.

        Used to detect a key-guessing attempt: many INVALID_SIGNATURE
        failures from one address in a short window is a different event from
        a misconfigured sender.
        """
        value = code.value if isinstance(code, SecurityEventCode) else str(code)
        row = self._conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE code = ? AND occurred_unix >= ?",
            (value, since_unix),
        ).fetchone()
        return int(row[0])

    def prune(self, before_unix: float) -> int:
        cursor = self._conn.execute(
            "DELETE FROM security_events WHERE occurred_unix < ?", (before_unix,)
        )
        return cursor.rowcount or 0


# ---------------------------------------------------------------------------
# Replay window
# ---------------------------------------------------------------------------


class ReplayWindow:
    """Hashes of accepted events, pruned on a rolling window.

    Two independent duplicate defences, and both are needed. The sequence test
    catches a verbatim replay. This catches a replay that a sender has
    re-sequenced - the hash is identical, so the event is provably the same
    bytes, but the sequence check alone would wave it through.
    """

    def __init__(self, conn: sqlite3.Connection, *, max_entries: int = 100_000) -> None:
        self._conn = conn
        self._max_entries = max_entries

    def seen(self, event_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM replay_window WHERE event_hash = ?", (event_hash,)
        ).fetchone()
        return row is not None

    def remember(
        self, event_hash: str, event_id: str, device_id: str, sequence: int
    ) -> bool:
        """Record a hash. Returns False if it was already present.

        The caller uses the return value to reject the event, so this is a
        test-and-set rather than a plain insert: two identical packets
        arriving on different threads must not both be accepted.
        """
        _, now_unix = _now()
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO replay_window (event_hash, event_id, device_id, "
            "sequence, first_seen_at) VALUES (?, ?, ?, ?, ?)",
            (event_hash, event_id, device_id, sequence, now_unix),
        )
        return (cursor.rowcount or 0) > 0

    def highest_sequence(self, device_id: str) -> int:
        row = self._conn.execute(
            "SELECT MAX(sequence) FROM replay_window WHERE device_id = ?", (device_id,)
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def prune(self, before_unix: float) -> int:
        """Drop entries older than the window.

        Truncation to ``max_entries`` also runs, so a flood of events inside a
        long window cannot grow the table without bound. The two-stage trim
        is deliberate: time-based expiry alone is not enough when
        ``replay_window_seconds`` is set large for a slow link.
        """
        removed = self._conn.execute(
            "DELETE FROM replay_window WHERE first_seen_at < ?", (before_unix,)
        ).rowcount or 0
        total = int(
            self._conn.execute("SELECT COUNT(*) FROM replay_window").fetchone()[0]
        )
        if total > self._max_entries:
            # Keep the newest entries: a fresh flood must not be able to evict
            # the hashes that would catch its own replays.
            trimmed = self._conn.execute(
                "DELETE FROM replay_window WHERE event_hash IN ("
                "  SELECT event_hash FROM replay_window ORDER BY first_seen_at "
                "  LIMIT ? OFFSET ?"
                ")",
                (total - self._max_entries, self._max_entries),
            ).rowcount or 0
            removed += trimmed
        return removed

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM replay_window").fetchone()[0])


# ---------------------------------------------------------------------------
# system_state
# ---------------------------------------------------------------------------


class StateRepository:
    """Durable node state.

    Kept separate from :class:`KVRepository` because these keys are
    load-bearing: ``highest_sequence`` in particular. A typo that lands in
    ``kv`` costs a preference; a typo that lands here could reset replay
    protection without anything reporting it.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def set(self, key: str, value: str) -> None:
        _check_key(key)
        _, now_text = _now()
        self._conn.execute(
            "INSERT INTO system_state (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = excluded.updated_at",
            (key, value, now_text),
        )

    def get(self, key: str, default: str | None = None) -> str | None:
        _check_key(key)
        row = self._conn.execute(
            "SELECT value FROM system_state WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.get(key)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError as exc:
            raise StorageError(
                f"system_state[{key!r}] holds {raw!r}, which is not an integer. "
                "Refusing to guess; restore the value or clear the key."
            ) from exc

    def delete(self, key: str) -> bool:
        _check_key(key)
        return bool(self._conn.execute("DELETE FROM system_state WHERE key = ?", (key,)).rowcount)

    def all(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self._conn.execute("SELECT * FROM system_state")}


# ---------------------------------------------------------------------------
# kv
# ---------------------------------------------------------------------------


class KVRepository:
    """Untrusted scratch space. Safe to lose, never read for a security decision."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def set(self, key: str, value: str) -> None:
        _, now_text = _now()
        self._conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = excluded.updated_at",
            (key, value, now_text),
        )

    def get(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def delete(self, key: str) -> bool:
        return bool(self._conn.execute("DELETE FROM kv WHERE key = ?", (key,)).rowcount)

    def all(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self._conn.execute("SELECT * FROM kv")}
