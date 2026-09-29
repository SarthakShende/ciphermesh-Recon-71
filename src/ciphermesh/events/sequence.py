"""Persistent monotonic event sequence.

The sequence is what a receiver uses to order events and to reject replays, so
its only hard requirement is this: **it must never go backwards**, across
restarts, crashes, and clock changes.

Three things conspire to break that in a naive implementation, and each is
handled explicitly here:

* **A crash between allocating and persisting.** The counter is written to
  disk *before* the number is returned to the caller, so a crash costs a
  skipped number, never a reused one. A gap is recoverable; a repeat is an
  undetectable replay.
* **A restored backup or a wiped database.** On startup the allocator takes
  ``max(persisted, database_max)`` rather than trusting the file. If the file
  is behind the data, events are allocated above the existing high-water mark
  so nothing collides with what is already stored.
* **A clock that steps backwards.** The sequence is a counter, never a
  timestamp. It is not derived from time at all, so NTP corrections cannot
  produce a repeat.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .. import paths
from ..errors import SequenceError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

#: Bumped if the on-disk layout changes.
SEQUENCE_FORMAT = "ciphermesh-sequence-v1"

#: First sequence number handed out. Zero is reserved as "no sequence".
FIRST_SEQUENCE = 1

__all__ = ["FIRST_SEQUENCE", "SEQUENCE_FORMAT", "SequenceAllocator"]


class SequenceAllocator:
    """Hands out strictly increasing integers and remembers the last one.

    Not a context manager and not process-shared: one allocator per node
    process, guarded by a lock. If two processes ever shared a state
    directory that is a deployment error the allocator cannot detect, which is
    why the systemd unit runs a single instance.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        start: int = FIRST_SEQUENCE,
        max_hint: Callable[[], int] | None = None,
    ) -> None:
        if start < 0:
            raise SequenceError(f"sequence start must not be negative, got {start}")
        self._path = Path(path) if path is not None else paths.sequence_state_path()
        self._start = start
        self._max_hint = max_hint
        self._lock = threading.Lock()
        self._current = self._reconcile()

    # -- allocation ---------------------------------------------------------

    def next(self) -> int:
        """Allocate the next sequence number and persist it before returning.

        If the write fails the number is *not* returned. Handing out a number
        that was never durably recorded is exactly how a replay becomes
        possible after a restart.
        """
        with self._lock:
            candidate = self._current + 1
            self._persist(candidate)
            self._current = candidate
            return candidate

    def peek(self) -> int:
        """The last allocated number; 0 before anything is allocated."""
        with self._lock:
            return self._current

    def observe(self, sequence: int) -> bool:
        """Raise the high-water mark to an externally seen sequence.

        Used on a receiver, which learns of higher sequences from inbound
        events rather than allocating them. Returns True if the mark moved,
        so the caller can decide whether the persist was worth it.
        """
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise SequenceError(f"cannot observe a non-sequence value: {sequence!r}")
        with self._lock:
            if sequence <= self._current:
                return False
            self._persist(sequence)
            self._current = sequence
            return True

    def reserve_at_least(self, sequence: int) -> bool:
        """Force the counter to ``sequence`` if it is behind.

        The explicit form of :meth:`observe`, used when rebuilding state after
        a restore.
        """
        return self.observe(sequence)

    # -- recovery -----------------------------------------------------------

    def _reconcile(self) -> int:
        """Establish the starting high-water mark.

        Takes the maximum of the persisted counter and whatever the caller
        says is already stored, so a stale file cannot cause a reuse.
        """
        persisted = self._read()
        hinted = 0
        if self._max_hint is not None:
            try:
                hinted = int(self._max_hint())
            except Exception as exc:
                # Storage may not be up yet at this point in startup. That is
                # not a reason to refuse to start, but it is not silent
                # either - the operator needs to know the self-heal was
                # skipped.
                LOG.warning(
                    "sequence high-water hint unavailable; using the persisted counter only",
                    extra={"event_code": "SEQUENCE_HINT_UNAVAILABLE", "detail": str(exc)},
                )
                hinted = 0
            else:
                if hinted < 0:
                    raise SequenceError(f"sequence high-water hint is negative: {hinted}")

        resolved = max(persisted, hinted, self._start - 1)
        if hinted > persisted:
            LOG.info(
                "sequence counter advanced to match stored events",
                extra={
                    "event_code": "SEQUENCE_RECONCILED",
                    "persisted": persisted,
                    "stored_max": hinted,
                    "next": resolved + 1,
                },
            )
        self._current = resolved
        if resolved != persisted:
            # Persist the reconciled value so a second restart without the
            # storage layer does not walk it back down again.
            self._persist(resolved)
        return resolved

    # -- persistence --------------------------------------------------------

    def _read(self) -> int:
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return 0
        except OSError as exc:
            raise SequenceError(f"cannot read sequence state {self._path}: {exc}") from exc

        try:
            data = json.loads(text)
        except ValueError:
            # A truncated counter file is recoverable: the database is the real
            # record. Losing it costs numbers, not trust.
            LOG.warning(
                "sequence state file is corrupt; rebuilding from storage",
                extra={"event_code": "SEQUENCE_RECONCILED", "path": str(self._path)},
            )
            return 0

        if not isinstance(data, dict) or data.get("format") != SEQUENCE_FORMAT:
            LOG.warning(
                "unrecognised sequence state format; rebuilding from storage",
                extra={"event_code": "SEQUENCE_RECONCILED", "path": str(self._path)},
            )
            return 0

        value = data.get("sequence")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            LOG.warning(
                "sequence state file holds a non-integer; rebuilding from storage",
                extra={"event_code": "SEQUENCE_RECONCILED", "path": str(self._path)},
            )
            return 0
        return value

    def _persist(self, value: int) -> None:
        payload = {
            "format": SEQUENCE_FORMAT,
            "sequence": value,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"

        tmp = self._path.with_name(self._path.name + ".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=paths.DIR_MODE)
            # os.fdopen takes ownership of the descriptor, so it is closed by
            # the context manager on both the happy and the failing path.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, paths.SECRET_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise SequenceError(
                f"cannot persist sequence state to {self._path}: {exc}. Refusing to hand out "
                "a sequence number that would be lost on restart."
            ) from exc

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"SequenceAllocator(path={str(self._path)!r}, current={self.peek()})"
