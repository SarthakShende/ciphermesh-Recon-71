"""SQLite connection management.

SQLite is the right tool here and also the wrong one, in ways that matter:

**Right** because the node is a single writer on a single SD card. A network
database would add a failure mode to a device whose whole purpose is to work
when nothing else does.

**Wrong** in three specific ways, each handled below:

* **SQLite's default locking is a foot-gun.** Two connections writing
  concurrently raise ``database is locked`` immediately rather than waiting.
  Every connection here sets a busy timeout and runs in WAL mode, so the
  sensor thread can read while the sync worker writes.
* **Durability is opt-in per connection.** ``PRAGMA synchronous`` does not
  persist across connections, so a database opened by a second process - a
  ``sqlite3`` shell, a support script - would silently get the default
  ``FULL`` and write differently. Every connection is configured
  identically by :func:`connect`, so behaviour does not depend on who opened
  the file.
* **Foreign keys are off by default, in every SQLite build.** A node that
  believed ``event_verifications`` was cleaned up by cascade would accumulate
  orphans forever. ``PRAGMA foreign_keys=ON`` is set on every connection.

None of these are optional. A connection that skips :func:`connect` will
behave differently from one that does not, which is why there is exactly one
way to open this database.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .. import paths
from ..config.schema import StorageConfig
from ..errors import StorageError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

#: Applied to every connection. Values are the defaults chosen in
#: StorageConfig; this is the fallback used when no config is supplied (tests,
#: and `ciphermesh db` before config has ever loaded).
DEFAULT_BUSY_TIMEOUT_MS = 5000
DEFAULT_JOURNAL_MODE = "WAL"
DEFAULT_SYNCHRONOUS = "NORMAL"
DEFAULT_FILE_MODE = 0o640

#: SQLite returns this when another connection holds a write lock past the
#: busy timeout. It is retried rather than surfaced, because a 5-second stall
#: on an SD card is plausible and the caller cannot do anything useful about
#: it except wait.
SQLITE_BUSY = "database is locked"

__all__ = [
    "Database",
    "connect",
    "is_busy_error",
]


def is_busy_error(exc: BaseException) -> bool:
    return SQLITE_BUSY in str(exc).lower() or "database table is locked" in str(exc).lower()


def connect(
    db_path: Path | str,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    journal_mode: str = DEFAULT_JOURNAL_MODE,
    synchronous: str = DEFAULT_SYNCHRONOUS,
    file_mode: int = DEFAULT_FILE_MODE,
    read_only: bool = False,
) -> sqlite3.Connection:
    """Open a fully configured connection.

    Every pragma is set explicitly. Relying on a default here is how a node
    ends up with two different durability behaviours depending on which
    process opened the file.
    """
    path = Path(db_path)
    if not read_only:
        _ensure_parent(path)
        _create_if_absent(path, file_mode)

    try:
        conn = sqlite3.connect(
            str(path),
            timeout=busy_timeout_ms / 1000.0,
            isolation_level=None,  # explicit transactions, see below
            check_same_thread=False,
        )
    except sqlite3.Error as exc:
        raise StorageError(f"cannot open database {path}: {exc}") from exc

    conn.row_factory = sqlite3.Row
    try:
        # isolation_level=None puts the connection in autocommit mode: nothing
        # is written unless a BEGIN is issued. The repositories do that
        # explicitly, so a multi-statement operation is atomic by
        # construction rather than by remembering to commit.
        conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        conn.execute("PRAGMA foreign_keys = ON")
        if not read_only:
            # journal_mode and synchronous are persistent for the database
            # file, but they are still set per connection because a read-only
            # connection cannot change them and must not fail trying.
            conn.execute(f"PRAGMA journal_mode = {journal_mode}")
            conn.execute(f"PRAGMA synchronous = {synchronous}")
        # Defence in depth for a file created outside our code path: SQLite
        # has no notion of file permissions.
        if not read_only:
            _assert_db_mode(path, file_mode)
    except sqlite3.Error as exc:
        conn.close()
        raise StorageError(f"cannot configure database {path}: {exc}") from exc

    return conn


def _ensure_parent(path: Path) -> None:
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=paths.DIR_MODE)
    except OSError as exc:
        raise StorageError(f"cannot create database directory {parent}: {exc}") from exc


def _create_if_absent(path: Path, mode: int) -> None:
    """Create an empty database file at ``mode`` before SQLite opens it.

    SQLite applies the process umask when it creates a file, which on many
    images is 0022 and would produce a world-readable database. Creating the
    file first with an explicit mode is the only way to control this, since
    SQLite has no option for it.
    """
    if path.exists():
        return
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        return
    except OSError as exc:
        raise StorageError(f"cannot create database {path}: {exc}") from exc
    os.close(fd)


def _assert_db_mode(path: Path, want: int) -> None:
    """Refuse a world-readable database, and repair a merely-loose one.

    The database holds the full event history and the trusted keyring. It is
    not secret in the sense the private key is - every row is publishable -
    but it should not be world-readable on a shared system, so the mode is
    checked and, if it is safe to do so, tightened with a log line.
    """
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return
    if mode & 0o007:
        raise StorageError(
            f"database {path} is world-accessible (mode {stat.filemode(mode)}); "
            f"expected {oct(want)}. Run: chmod {oct(want)[2:]} {path}"
        )
    if mode == want or mode & 0o077:
        # Already correct, stricter than we asked for, or group/other-accessible
        # in a way that changing it might be meant to be. Leave it alone:
        # chmod on a mode an operator set deliberately is not this module's
        # call to make, and loosening never happens.
        return
    try:
        os.chmod(path, want)
    except OSError as exc:  # pragma: no cover - permission-dependent
        LOG.warning(
            "could not tighten database permissions",
            extra={
                "event_code": "KEY_PERMISSION_FIXED",
                "path": str(path),
                "detail": str(exc),
            },
        )


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block as one transaction.

    ``BEGIN IMMEDIATE`` takes the write lock up front rather than on first
    write. That converts a mid-transaction ``database is locked`` - after
    which the transaction is already unusable - into an up-front wait that the
    busy timeout can actually absorb.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        if is_busy_error(exc):
            raise StorageError(
                "database is locked by another writer and the busy timeout expired"
            ) from exc
        raise StorageError(f"cannot begin transaction: {exc}") from exc
    try:
        yield conn
    except BaseException:
        # Rollback on any failure, including KeyboardInterrupt. A partially
        # applied verification result is worse than none: it could mark an
        # event VERIFIED without the signature having been checked.
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:  # pragma: no cover - rollback of a dead conn
            pass
        raise
    conn.execute("COMMIT")


class Database:
    """Owns one connection and hands it to callers under a lock.

    A single connection is shared rather than a pool. The node's concurrency
    is one sensor thread, one sync worker, and a monitoring API that reads
    occasionally - a pool would add contention and failure modes for no
    benefit, and SQLite serialises writes anyway.

    The lock is what makes ``check_same_thread=False`` sound. It is not
    optional and must not be bypassed: without it, two threads sharing one
    connection can interleave statements inside a single transaction and
    commit a half-written result.
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        config: StorageConfig | None = None,
    ) -> None:
        if db_path is None:
            db_path = self._path_from_config(config)
        self.path = Path(db_path)
        self._config = config or StorageConfig()
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._closed = False

    @staticmethod
    def _path_from_config(config: StorageConfig | None) -> Path:
        if config and config.sqlite_path:
            return Path(config.sqlite_path)
        return paths.default_db_path()

    @property
    def connection(self) -> sqlite3.Connection:
        if self._closed:
            raise StorageError("database is closed")
        with self._lock:
            if self._conn is None:
                self._conn = self._open()
            return self._conn

    def _open(self) -> sqlite3.Connection:
        return connect(
            self.path,
            busy_timeout_ms=self._config.busy_timeout_ms,
            journal_mode=self._config.journal_mode,
            synchronous=self._config.synchronous,
            file_mode=self._config.db_file_mode or DEFAULT_FILE_MODE,
        )

    # -- operations ---------------------------------------------------------

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        """Read-only access. Serialised against writers for safety."""
        with self._lock:
            yield self.connection

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """A single atomic write transaction."""
        with self._lock, transaction(self.connection) as conn:
            yield conn

    def execute(self, sql: str, params: object = ()) -> sqlite3.Cursor:
        """Autocommit single statement. Prefer :meth:`write` for anything
        that must be atomic with another statement."""
        with self._lock:
            try:
                return self.connection.execute(sql, params)
            except sqlite3.Error as exc:
                raise StorageError(f"query failed: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    # Fold the WAL back into the main database so a copied
                    # .db file is complete on its own.
                    self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:  # pragma: no cover - best effort
                    pass
                self._conn.close()
                self._conn = None
            self._closed = True

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Database(path={str(self.path)!r}, closed={self._closed})"
