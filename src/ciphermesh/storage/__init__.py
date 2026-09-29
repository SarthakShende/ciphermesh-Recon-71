"""SQLite storage layer.

One :class:`Database` per process, opened through
:func:`ciphermesh.storage.db.connect` so every connection is configured
identically, and one repository per table. Repositories take a live
connection rather than opening their own, which keeps transaction boundaries
visible at the call site: a caller that needs to store an event and record its
verification atomically wraps both in one ``db.write()``.
"""

from __future__ import annotations

from ..errors import DuplicateEventError
from .db import Database, connect, is_busy_error, transaction
from .devices import DeviceRecord, DeviceRepository
from .events import EventRecord, EventRepository
from .migrations import (
    Migration,
    applied_migrations,
    bootstrap_and_migrate,
    current_version,
    discover,
    migrate,
    pending,
)
from .state import (
    STATE_KEYS,
    STATE_LAST_SYNC,
    STATE_SEQUENCE,
    KVRepository,
    ReplayWindow,
    SecurityEventRepository,
    SecurityRecord,
    StateRepository,
)
from .sync_queue import QueueItem, SyncQueueRepository
from .verifications import (
    STAGE_COUNT,
    STAGE_NAMES,
    StageResult,
    VerificationAttempt,
    VerificationRepository,
)

__all__ = [
    "STAGE_COUNT",
    "STAGE_NAMES",
    "STATE_KEYS",
    "STATE_LAST_SYNC",
    "STATE_SEQUENCE",
    "Database",
    "DeviceRecord",
    "DeviceRepository",
    "DuplicateEventError",
    "EventRecord",
    "EventRepository",
    "KVRepository",
    "Migration",
    "QueueItem",
    "ReplayWindow",
    "SecurityEventRepository",
    "SecurityRecord",
    "StageResult",
    "StateRepository",
    "SyncQueueRepository",
    "VerificationAttempt",
    "VerificationRepository",
    "applied_migrations",
    "bootstrap_and_migrate",
    "connect",
    "current_version",
    "discover",
    "is_busy_error",
    "migrate",
    "pending",
    "transaction",
]
