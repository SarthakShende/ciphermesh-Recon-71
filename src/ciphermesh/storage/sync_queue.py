"""The offline-first upload queue.

The queue exists so that a node with no internet is still a working node. It
is not a retry decorator: records are persisted, survive restarts, and are
claimed in a way that tolerates a process dying mid-upload.

Four properties matter more than throughput here:

* **Claim before send, never during.** A record is moved PENDING -> SYNCING
  and committed *before* the request goes out. If the process dies after the
  server accepted the upload but before the response, the record is stuck in
  SYNCING - and a stuck record is recoverable, whereas a record left PENDING
  would be re-sent forever with no way to tell.

* **Idempotent enqueue.** The unique index on (kind, ref_id) means re-queueing
  an event updates the existing row. Without it, every reconnect would
  re-upload the entire backlog.

* **Backoff is computed, not stored as a guess.** ``next_attempt_at`` is an
  absolute unix time the caller supplies, computed by
  :func:`ciphermesh.sync.backoff`. Storing "retry in 15 seconds" as a
  duration would drift across a restart and would be meaningless after a
  long sleep.

* **FAILED is terminal, not a retry loop.** After ``sync.max_attempts`` a
  record stops being claimed and waits for an operator. A node that retries
  forever against a broken backend burns its SD card and hides the outage.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..constants import QueueStatus
from ..errors import StorageError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

KIND_EVENT = "EVENT"
KIND_REGISTRATION = "REGISTRATION"
KIND_SECURITY_EVENT = "SECURITY_EVENT"

VALID_KINDS = (KIND_EVENT, KIND_REGISTRATION, KIND_SECURITY_EVENT)

__all__ = [
    "KIND_EVENT",
    "KIND_REGISTRATION",
    "KIND_SECURITY_EVENT",
    "QueueItem",
    "SyncQueueRepository",
]


def _now() -> tuple[str, float]:
    instant = datetime.now(timezone.utc)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ"), instant.timestamp()


@dataclass(frozen=True, slots=True)
class QueueItem:
    id: int
    kind: str
    ref_id: str
    payload: str
    status: str
    attempts: int
    next_attempt_at: float
    last_error: str | None
    created_at: str
    updated_at: str
    synced_at: str | None

    @property
    def body(self) -> Any:
        """The parsed payload, for handing to the HTTP client."""
        return json.loads(self.payload)

    @property
    def is_terminal(self) -> bool:
        return self.status in (QueueStatus.SYNCED.value, QueueStatus.FAILED.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "ref_id": self.ref_id,
            "status": self.status,
            "attempts": self.attempts,
            "next_attempt_at": self.next_attempt_at,
            "last_error": self.last_error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "synced_at": self.synced_at,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> QueueItem:
        return cls(
            id=int(row["id"]),
            kind=row["kind"],
            ref_id=row["ref_id"],
            payload=row["payload"],
            status=row["status"],
            attempts=int(row["attempts"]),
            next_attempt_at=float(row["next_attempt_at"]),
            last_error=row["last_error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            synced_at=row["synced_at"],
        )


class SyncQueueRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # -- enqueue ------------------------------------------------------------

    def enqueue(
        self,
        kind: str,
        ref_id: str,
        payload: Any,
        *,
        next_attempt_at: float = 0.0,
    ) -> int:
        """Add a record, or refresh the one that already exists.

        Idempotent by (kind, ref_id). A record that has already been SYNCED is
        not resurrected: re-enqueueing an event that reached the server would
        duplicate it upstream. To genuinely resend, call :meth:`requeue`.
        """
        if kind not in VALID_KINDS:
            raise StorageError(f"kind must be one of {VALID_KINDS}, got {kind!r}")
        if not ref_id:
            raise StorageError("ref_id must not be empty")

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        now_text, now_unix = _now()

        existing = self._conn.execute(
            "SELECT id, status FROM sync_queue WHERE kind = ? AND ref_id = ?",
            (kind, ref_id),
        ).fetchone()
        if existing is not None:
            if existing["status"] == QueueStatus.SYNCED.value:
                return int(existing["id"])
            self._conn.execute(
                "UPDATE sync_queue SET payload = ?, next_attempt_at = MIN(?, ?), "
                "updated_at = ?, last_error = NULL WHERE id = ?",
                (body, next_attempt_at, now_unix, now_text, existing["id"]),
            )
            return int(existing["id"])

        cursor = self._conn.execute(
            "INSERT INTO sync_queue (kind, ref_id, payload, status, attempts, "
            "next_attempt_at, created_at, updated_at) "
            "VALUES (?, ?, ?, 'PENDING', 0, ?, ?, ?)",
            (kind, ref_id, body, next_attempt_at, now_text, now_text),
        )
        return int(cursor.lastrowid or 0)

    def enqueue_event(self, signed, event_row_id: int | None = None) -> int:
        """Queue a signed event for upload.

        The payload captured is the canonical signed form, so the cloud backend
        can verify the same bytes this node verified.
        """
        payload = {
            "event": signed.to_wire_dict(),
            "key_id": signed.key_id,
            "signature": signed.signature.hex(),
        }
        return self.enqueue(KIND_EVENT, signed.event.event_id, payload)

    def enqueue_registration(self, device_id: str, registration: Any) -> int:
        return self.enqueue(KIND_REGISTRATION, device_id, registration)

    # -- claim --------------------------------------------------------------

    #: How long a claim is held before another worker may take it over. A
    #: crashed worker's records become claimable again only after this, so a
    #: slow-but-alive upload is not stolen out from under it.
    DEFAULT_LEASE_SECONDS = 300.0

    def claim(
        self,
        *,
        batch_size: int = 25,
        now: float | None = None,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
    ) -> list[QueueItem]:
        """Claim up to ``batch_size`` eligible records.

        Eligibility: PENDING (or a SYNCING record whose lease has expired) and
        ``next_attempt_at`` already reached. Records are returned in
        ``created_at`` order so the backlog uploads oldest-first.
        """
        if batch_size < 1:
            raise StorageError(f"batch_size must be at least 1, got {batch_size}")
        moment = now if now is not None else _now()[1]
        now_text = _now()[0]

        # Reclaim expired leases first: a crash mid-upload leaves records in
        # SYNCING, and without this they would never be retried. The lease is
        # what stops a second claim from picking up a record that is still
        # being uploaded right now.
        self._conn.execute(
            "UPDATE sync_queue SET status = 'PENDING' WHERE status = 'SYNCING' "
            "AND next_attempt_at <= ?",
            (moment,),
        )

        rows = self._conn.execute(
            "SELECT id FROM sync_queue WHERE status = 'PENDING' AND next_attempt_at <= ? "
            "ORDER BY created_at, id LIMIT ?",
            (moment, batch_size),
        ).fetchall()
        if not rows:
            return []

        ids = [int(r["id"]) for r in rows]
        placeholders = ",".join("?" * len(ids))
        # Claiming pushes next_attempt_at out to the end of the lease, so the
        # record is not re-offered until either it is marked SYNCED/FAILED or
        # the lease lapses because the worker died.
        self._conn.execute(
            f"UPDATE sync_queue SET status = 'SYNCING', updated_at = ?, "
            f"next_attempt_at = ? WHERE id IN ({placeholders})",
            (now_text, moment + lease_seconds, *ids),
        )
        claimed = self._conn.execute(
            f"SELECT * FROM sync_queue WHERE id IN ({placeholders}) ORDER BY created_at, id",
            ids,
        ).fetchall()
        return [QueueItem.from_row(r) for r in claimed]

    # -- completion ---------------------------------------------------------

    def mark_synced(self, queue_id: int) -> None:
        now_text, _ = _now()
        self._conn.execute(
            "UPDATE sync_queue SET status = 'SYNCED', synced_at = ?, updated_at = ?, "
            "last_error = NULL WHERE id = ?",
            (now_text, now_text, queue_id),
        )
        if self._kind_of(queue_id) == KIND_EVENT:
            self._conn.execute(
                "UPDATE events SET synced_at = ? WHERE event_id = "
                "(SELECT ref_id FROM sync_queue WHERE id = ?)",
                (now_text, queue_id),
            )

    def mark_failed(self, queue_id: int, error: str, next_attempt_at: float) -> int:
        """Record a failed attempt and schedule the retry.

        Returns the new attempt count. The caller decides whether that count
        has reached ``sync.max_attempts``; when it has, it calls
        :meth:`give_up` rather than scheduling another retry.
        """
        now_text, _ = _now()
        self._conn.execute(
            "UPDATE sync_queue SET status = 'PENDING', attempts = attempts + 1, "
            "last_error = ?, next_attempt_at = ?, updated_at = ? WHERE id = ?",
            (error[:2000], next_attempt_at, now_text, queue_id),
        )
        row = self._conn.execute(
            "SELECT attempts FROM sync_queue WHERE id = ?", (queue_id,)
        ).fetchone()
        return int(row["attempts"]) if row else 0

    def give_up(self, queue_id: int, error: str) -> None:
        """Move to FAILED, terminal until an operator acts.

        Records stay in the table rather than being deleted: a silent upload
        that vanishes is far worse than a visible one that failed.
        """
        now_text, _ = _now()
        self._conn.execute(
            "UPDATE sync_queue SET status = 'FAILED', last_error = ?, updated_at = ? "
            "WHERE id = ?",
            (error[:2000], now_text, queue_id),
        )
        LOG.warning(
            "sync record abandoned after repeated failures",
            extra={
                "event_code": "SYNC_FAILED",
                "queue_id": queue_id,
                "detail": error[:200],
            },
        )

    def requeue(self, queue_id: int, *, reset_attempts: bool = True) -> bool:
        """Return a FAILED or SYNCED record to PENDING.

        This is the operator-facing recovery path (`ciphermesh sync retry`).
        """
        now_text, now_unix = _now()
        if reset_attempts:
            sql = (
                "UPDATE sync_queue SET status = 'PENDING', attempts = 0, last_error = NULL, "
                "next_attempt_at = ?, updated_at = ? WHERE id = ?"
            )
            params: tuple = (now_unix, now_text, queue_id)
        else:
            # Preserve the existing count: clearing it would make the retry
            # loop treat a repeatedly-failing record as a first attempt.
            sql = (
                "UPDATE sync_queue SET status = 'PENDING', last_error = NULL, "
                "next_attempt_at = ?, updated_at = ? WHERE id = ?"
            )
            params = (now_unix, now_text, queue_id)
        cursor = self._conn.execute(sql, params)
        return bool(cursor.rowcount)

    def requeue_all_failed(self) -> int:
        now_text, now_unix = _now()
        cursor = self._conn.execute(
            "UPDATE sync_queue SET status = 'PENDING', attempts = 0, last_error = NULL, "
            "next_attempt_at = ?, updated_at = ? WHERE status = 'FAILED'",
            (now_unix, now_text),
        )
        return cursor.rowcount or 0

    def _kind_of(self, queue_id: int) -> str | None:
        row = self._conn.execute(
            "SELECT kind FROM sync_queue WHERE id = ?", (queue_id,)
        ).fetchone()
        return row["kind"] if row else None

    # -- reads --------------------------------------------------------------

    def get(self, queue_id: int) -> QueueItem | None:
        row = self._conn.execute("SELECT * FROM sync_queue WHERE id = ?", (queue_id,)).fetchone()
        return QueueItem.from_row(row) if row else None

    def get_by_ref(self, kind: str, ref_id: str) -> QueueItem | None:
        row = self._conn.execute(
            "SELECT * FROM sync_queue WHERE kind = ? AND ref_id = ?", (kind, ref_id)
        ).fetchone()
        return QueueItem.from_row(row) if row else None

    def list_all(
        self, *, status: QueueStatus | None = None, limit: int = 100
    ) -> list[QueueItem]:
        sql = "SELECT * FROM sync_queue"
        params: list[Any] = []
        if status is not None:
            sql += " WHERE status = ?"
            params.append(status.value)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [QueueItem.from_row(r) for r in self._conn.execute(sql, params)]

    def counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM sync_queue GROUP BY status"
        )
        return {r["status"]: int(r["n"]) for r in rows}

    def depth(self) -> int:
        """Records still awaiting a successful upload."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM sync_queue WHERE status IN ('PENDING', 'SYNCING')"
        ).fetchone()
        return int(row[0])

    def oldest_pending_age(self, now: float | None = None) -> float | None:
        """Seconds since the oldest record was enqueued, or None if empty.

        The single most useful number for an operator: "the queue has been
        stuck for 40 minutes" says far more than a count of 812.
        """
        moment = now if now is not None else _now()[1]
        row = self._conn.execute(
            "SELECT MIN(created_at) AS oldest FROM sync_queue "
            "WHERE status IN ('PENDING', 'SYNCING')"
        ).fetchone()
        if not row or not row["oldest"]:
            return None
        created = datetime.strptime(row["oldest"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        return moment - created.timestamp()

    # -- maintenance --------------------------------------------------------

    def prune_synced(self, older_than_unix: float) -> int:
        cursor = self._conn.execute(
            "DELETE FROM sync_queue WHERE status = 'SYNCED' "
            "AND COALESCE(synced_at, updated_at) < ?",
            (_iso(older_than_unix),),
        )
        return cursor.rowcount or 0


def _iso(unix: float) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
