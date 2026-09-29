"""Event persistence.

Three decisions in this module are load-bearing:

* **The signed payload is stored verbatim.** ``events.payload`` holds the exact
  canonical JSON that was signed. Re-verification reads that column and never
  re-serialises from the individual columns, because the signature covers the
  canonical form - and if the schema ever changes a field's representation,
  re-serialising would produce a different message and invalidate every
  signature ever made. Historical events stay verifiable forever.

* **Rejected events are stored too.** A receiver that throws away what it
  rejects cannot show an operator what was trying to impersonate it. The
  ``verification_status`` column distinguishes the two, and no code path
  deletes an unverified event except retention pruning.

* **The sequence is unique per device, enforced by the database.** The
  pipeline checks it first, but a bug in the pipeline must not be the only
  thing standing between a replay and a second accepted copy. The unique
  index is the backstop; a violation is reported as REPLAY_REJECTED rather
  than raised.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..constants import EventType, Unit, VerificationStatus
from ..crypto import canonical_bytes
from ..errors import DuplicateEventError, StorageError
from ..events.model import Event, SignedEvent, parse_timestamp
from ..logging_setup import get_logger

LOG = get_logger(__name__)

#: How many rows a single listing call returns. The API paginates; a
#: pathological "return every event" would exhaust the SD card's page cache
#: and starve the sensor loop.
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000

__all__ = ["EventRecord", "EventRepository"]


def _now() -> tuple[str, float]:
    instant = datetime.now(timezone.utc)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ"), instant.timestamp()


@dataclass(frozen=True, slots=True)
class EventRecord:
    id: int
    event_id: str
    version: int
    device_id: str
    event_type: str
    value: float
    unit: str
    sequence: int
    timestamp: str
    timestamp_unix: float
    event_hash: str
    key_id: str
    signature: bytes
    payload: str
    verification_status: str
    verified_at: str | None
    origin: str
    received_at: str
    sent_at: str | None
    synced_at: str | None
    device_name: str | None = None
    location: str | None = None

    @property
    def accepted(self) -> bool:
        return self.verification_status == VerificationStatus.VERIFIED.value

    @property
    def signature_b64(self) -> str:
        import base64

        return base64.b64encode(self.signature).decode("ascii")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "version": self.version,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "device_name": self.device_name,
            "location": self.location,
            "value": self.value,
            "unit": self.unit,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_hash": self.event_hash,
            "key_id": self.key_id,
            "signature": self.signature_b64,
            "verification_status": self.verification_status,
            "origin": self.origin,
            "received_at": self.received_at,
            "sent_at": self.sent_at,
            "synced_at": self.synced_at,
        }

    def to_signed_event(self) -> SignedEvent:
        """Rebuild a :class:`SignedEvent` for re-verification.

        Reads the stored payload rather than reconstructing it, so the bytes
        being verified are the bytes the sender signed.
        """
        return SignedEvent.from_wire(
            json.loads(self.payload), self.signature, self.key_id
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> EventRecord:
        return cls(
            id=int(row["id"]),
            event_id=row["event_id"],
            version=int(row["version"]),
            device_id=row["device_id"],
            event_type=row["event_type"],
            value=row["value"],
            unit=row["unit"],
            sequence=int(row["sequence"]),
            timestamp=row["timestamp"],
            timestamp_unix=float(row["timestamp_unix"]),
            event_hash=row["event_hash"],
            key_id=row["key_id"],
            signature=bytes(row["signature"]),
            payload=row["payload"],
            verification_status=row["verification_status"],
            verified_at=row["verified_at"],
            origin=row["origin"],
            received_at=row["received_at"],
            sent_at=row["sent_at"],
            synced_at=row["synced_at"],
            device_name=row["device_name"],
            location=row["location"],
        )


class EventRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # -- writes -------------------------------------------------------------

    def store(
        self,
        signed: SignedEvent,
        status: VerificationStatus,
        *,
        origin: str = "remote",
        received_at: str | None = None,
        enqueue: bool = False,
    ) -> int:
        """Persist an event and return its row id.

        ``status`` is the *receiver's* conclusion and is deliberately not part
        of the signed payload, so it can be updated later without invalidating
        the signature.
        """
        if origin not in ("local", "remote"):
            raise StorageError(f"origin must be 'local' or 'remote', got {origin!r}")

        event = signed.event
        payload_json = canonical_bytes(event.canonical_payload()).decode("utf-8")
        received = received_at or _now()[0]

        if self.get(event.event_id) is not None:
            raise DuplicateEventError(
                f"event {event.event_id} is already stored; store is not idempotent "
                "so a caller must check first"
            )
        if self.is_sequence_taken(event.device_id, event.sequence):
            raise DuplicateEventError(
                f"device {event.device_id} has already used sequence "
                f"{event.sequence}; this is a replay"
            )

        try:
            timestamp_unix = parse_timestamp(event.timestamp).timestamp()
        except Exception as exc:
            # Event.__post_init__ already validated this, so reaching here
            # means the column was written by something else. Refuse rather
            # than store a row whose time bounds cannot be queried.
            raise StorageError(f"cannot store event with bad timestamp: {exc}") from exc

        try:
            cursor = self._conn.execute(
                "INSERT INTO events (event_id, version, device_id, event_type, device_name, "
                "location, value, unit, sequence, timestamp, timestamp_unix, event_hash, "
                "key_id, signature, payload, verification_status, verified_at, origin, "
                "received_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.version,
                    event.device_id,
                    event.event_type.value,
                    event.device_name,
                    event.location,
                    event.value,
                    event.unit.value,
                    event.sequence,
                    event.timestamp,
                    timestamp_unix,
                    event.hash(),
                    signed.key_id,
                    signed.signature,
                    payload_json,
                    status.value,
                    received if status.accepted else None,
                    origin,
                    received,
                ),
            )
        except sqlite3.IntegrityError as exc:
            # The unique indexes are the backstop against a concurrent writer
            # winning the race between the check above and this insert, so the
            # constraint is reported as a duplicate rather than a raw
            # IntegrityError the caller has to string-match.
            raise DuplicateEventError(
                f"could not store event {event.event_id}: {exc}"
            ) from exc
        row_id = int(cursor.lastrowid or 0)

        if enqueue:
            from .sync_queue import SyncQueueRepository

            SyncQueueRepository(self._conn).enqueue_event(signed, row_id)

        return row_id

    def store_rejected(self, signed: SignedEvent, status: VerificationStatus) -> int:
        """Store an event that failed verification.

        Kept as a distinct method so a caller cannot accidentally enqueue a
        rejected event for upload: sending an event this node believes is
        forged to the cloud would be a data-integrity incident in its own
        right.
        """
        if status.accepted:
            raise StorageError("store_rejected called with an accepting status")
        return self.store(signed, status, origin="remote", enqueue=False)

    def set_status(self, row_id: int, status: VerificationStatus) -> None:
        """Update the verification outcome after a later stage ran."""
        verified_at = _now()[0] if status.accepted else None
        self._conn.execute(
            "UPDATE events SET verification_status = ?, verified_at = ? WHERE id = ?",
            (status.value, verified_at, row_id),
        )

    def mark_sent(self, event_id: str) -> None:
        self._conn.execute(
            "UPDATE events SET sent_at = ? WHERE event_id = ?", (_now()[0], event_id)
        )

    def mark_synced(self, event_id: str) -> None:
        self._conn.execute(
            "UPDATE events SET synced_at = ? WHERE event_id = ?", (_now()[0], event_id)
        )

    # -- reads --------------------------------------------------------------

    def get(self, event_id: str) -> EventRecord | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return EventRecord.from_row(row) if row else None

    def get_by_hash(self, event_hash: str) -> EventRecord | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_hash = ?", (event_hash,)
        ).fetchone()
        return EventRecord.from_row(row) if row else None

    def is_sequence_taken(self, device_id: str, sequence: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM events WHERE device_id = ? AND sequence = ?",
            (device_id, sequence),
        ).fetchone()
        return row is not None

    def highest_sequence(self, device_id: str) -> int:
        """The highest sequence ever stored for a device, verified or not.

        Used by the sequence allocator to self-heal. It counts *all* rows
        rather than only verified ones, because reusing a number that an
        attacker has already used is exactly what must never happen.
        """
        row = self._conn.execute(
            "SELECT MAX(sequence) FROM events WHERE device_id = ?", (device_id,)
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def latest(
        self,
        device_id: str | None = None,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> list[EventRecord]:
        if limit < 1:
            raise StorageError(f"limit must be at least 1, got {limit}")
        limit = min(limit, MAX_PAGE_SIZE)
        sql = "SELECT * FROM events"
        params: list[Any] = []
        if device_id is not None:
            sql += " WHERE device_id = ?"
            params.append(device_id)
        sql += " ORDER BY timestamp_unix DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [EventRecord.from_row(r) for r in self._conn.execute(sql, params)]

    def between(self, start_unix: float, end_unix: float, *, limit: int = DEFAULT_PAGE_SIZE) -> list[EventRecord]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE timestamp_unix BETWEEN ? AND ? "
            "ORDER BY timestamp_unix DESC LIMIT ?",
            (start_unix, end_unix, min(limit, MAX_PAGE_SIZE)),
        )
        return [EventRecord.from_row(r) for r in rows]

    def unsynced(self, *, limit: int = DEFAULT_PAGE_SIZE) -> list[EventRecord]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE synced_at IS NULL AND origin = 'local' "
            "AND verification_status = ? ORDER BY id LIMIT ?",
            (VerificationStatus.VERIFIED.value, min(limit, MAX_PAGE_SIZE)),
        )
        return [EventRecord.from_row(r) for r in rows]

    def iter_all(self, *, batch: int = 500) -> Iterator[EventRecord]:
        """Stream every row.

        Batched rather than loaded whole: a node that has been up for a year
        has far more events than fit comfortably in memory, and retention
        pruning must not require that they do.
        """
        offset = 0
        while True:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id LIMIT ? OFFSET ?", (batch, offset)
            ).fetchall()
            if not rows:
                return
            for row in rows:
                yield EventRecord.from_row(row)
            offset += batch

    def count(self, *, since_unix: float | None = None) -> int:
        if since_unix is None:
            return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        row = self._conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp_unix >= ?", (since_unix,)
        ).fetchone()
        return int(row[0])

    def count_by_status(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT verification_status, COUNT(*) AS n FROM events GROUP BY verification_status"
        )
        return {r["verification_status"]: int(r["n"]) for r in rows}

    # -- maintenance --------------------------------------------------------

    def prune(self, before_unix: float) -> int:
        """Delete events older than a cut-off. Returns the number removed.

        Batched to keep each transaction short, so a large prune does not
        starve the sensor loop behind an exclusive lock.
        """
        total = 0
        while True:
            cursor = self._conn.execute(
                "DELETE FROM events WHERE id IN ("
                "  SELECT id FROM events WHERE timestamp_unix < ? LIMIT 500"
                ")",
                (before_unix,),
            )
            deleted = cursor.rowcount or 0
            total += deleted
            if deleted < 500:
                return total

    def vacuum(self) -> None:
        """Reclaim space and refresh the query planner's statistics.

        Incremental rather than a full VACUUM so it does not rewrite the
        whole database on an SD card at a predictable bad moment.
        """
        self._conn.execute("PRAGMA incremental_vacuum")
        self._conn.execute("ANALYZE")

    # -- projections --------------------------------------------------------

    def to_model(self, record: EventRecord) -> Event:
        """Rebuild the signed :class:`Event` from stored columns.

        Only for display. Verification must use
        :meth:`EventRecord.to_signed_event`, which reads the stored payload.
        """
        return Event(
            event_id=record.event_id,
            device_id=record.device_id,
            event_type=EventType(record.event_type),
            value=record.value,
            unit=Unit(record.unit),
            sequence=record.sequence,
            timestamp=record.timestamp,
            version=record.version,
            device_name=record.device_name,
            location=record.location,
        )
