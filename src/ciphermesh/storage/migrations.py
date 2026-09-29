"""Versioned schema migrations.

The design constraints:

* **Forward only.** A migration is applied exactly once and never edited. The
  runner records a SHA-256 of every file it applies; if a file later changes,
  startup fails rather than running a schema the code no longer matches.
  Editing an applied migration is the single most damaging thing an operator
  can do to a deployed node, and this makes it a startup error instead of
  silent corruption.
* **One transaction per migration.** Either the whole file lands or none of
  it does. SQLite makes DDL transactional, so this is achievable, and a
  half-applied schema would leave the node unable to start on the next boot.
* **Files are the source of truth, not the database.** The runner discovers
  migrations by reading the directory. A migration applied on PI-A and not on
  PI-B is a deployment problem the runner surfaces, not one it papers over.

`schema_migrations` is created before the first migration is read, so a fresh
database can bootstrap itself.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import paths
from ..errors import MigrationError, StorageError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

#: `NNN_snake_case_name.sql`. The number is the version and must be unique.
#: The name is stored for operator legibility only; the version is the key.
_MIGRATION_RE = re.compile(r"^(?P<version>\d{3,})_(?P<name>[a-z0-9_]+)\.sql$")

_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    checksum    TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL
)
"""

__all__ = [
    "Migration",
    "applied_migrations",
    "bootstrap_and_migrate",
    "current_version",
    "discover",
    "migrate",
    "pending",
]


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    path: Path

    @property
    def checksum(self) -> str:
        """SHA-256 of the file's bytes.

        Byte-exact rather than normalised, so a change of whitespace is also
        detected. That is intentional: the file is a build artefact of the
        deployed version, and any difference means it was edited.
        """
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.version:04d}_{self.name}"


def discover(directory: Path | None = None) -> list[Migration]:
    """Find every migration file, ordered by version.

    A file that does not match the naming convention is an error, not
    something to skip. Skipping it would mean a typo silently removes a
    schema change from the deployment.
    """
    base = Path(directory) if directory is not None else paths.migrations_dir()
    if not base.is_dir():
        raise MigrationError(
            f"migrations directory {base} does not exist. The package is "
            "incomplete; reinstall ciphermesh-edge."
        )

    found: dict[int, Migration] = {}
    for entry in sorted(base.iterdir()):
        if not entry.is_file() or entry.suffix != ".sql":
            continue
        match = _MIGRATION_RE.match(entry.name)
        if not match:
            raise MigrationError(
                f"migration {entry.name} does not match NNN_snake_case_name.sql; "
                "refusing to start because a schema change may be silently skipped"
            )
        version = int(match.group("version"))
        if version in found:
            raise MigrationError(
                f"duplicate migration version {version}: "
                f"{found[version].path.name} and {entry.name}"
            )
        found[version] = Migration(version, match.group("name"), entry)

    return [found[v] for v in sorted(found)]


def applied_migrations(conn: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    """Return ``{version: (name, checksum)}`` for migrations already applied."""
    try:
        rows = conn.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
    except sqlite3.OperationalError as exc:
        # The table is created by _bootstrap below, so this only fires if the
        # connection is read-only or the file is not a database.
        raise MigrationError(f"cannot read schema_migrations: {exc}") from exc
    return {int(r["version"]): (r["name"], r["checksum"]) for r in rows}


def current_version(conn: sqlite3.Connection) -> int:
    """Highest applied version, or 0 on a fresh database."""
    versions = applied_migrations(conn)
    return max(versions) if versions else 0


def pending(conn: sqlite3.Connection, directory: Path | None = None) -> list[Migration]:
    """Migrations that have not been applied, in order."""
    done = applied_migrations(conn)
    return [m for m in discover(directory) if m.version not in done]


def migrate(
    conn: sqlite3.Connection,
    directory: Path | None = None,
    *,
    target: int | None = None,
) -> list[Migration]:
    """Apply pending migrations up to ``target``.

    Returns the migrations actually applied, which is empty when the database
    is already current - the common case on every restart.
    """
    # The bookkeeping table has to exist before it can be read. Doing this
    # here rather than requiring every caller to remember makes `migrate` the
    # single entry point a bootstrap has to know about.
    _bootstrap(conn)
    migrations = discover(directory)
    done = applied_migrations(conn)

    _verify_applied_unchanged(migrations, done)

    outstanding = [m for m in migrations if m.version not in done]
    if target is not None:
        outstanding = [m for m in outstanding if m.version <= target]

    applied: list[Migration] = []
    for migration in outstanding:
        _apply(conn, migration)
        applied.append(migration)

    if applied:
        LOG.info(
            "schema migrations applied",
            extra={
                "event_code": "MIGRATIONS_APPLIED",
                "versions": [m.version for m in applied],
                "now_at": current_version(conn),
            },
        )
    return applied


def _verify_applied_unchanged(
    migrations: list[Migration], done: dict[int, tuple[str, str]]
) -> None:
    """Refuse to start if a previously applied migration file was edited.

    This is the check that makes forward-only real. Without it, an operator
    who "just fixes a typo" in an applied migration leaves the database in a
    state the running code does not describe, and nothing reports it.
    """
    by_version = {m.version: m for m in migrations}
    for version, (name, checksum) in sorted(done.items()):
        migration = by_version.get(version)
        if migration is None:
            raise MigrationError(
                f"migration {version:04d}_{name} is recorded as applied but its file "
                "is missing. The database is ahead of the installed package; "
                f"reinstall the same version of ciphermesh-edge. Downgrading is not "
                "supported."
            )
        actual = migration.checksum
        if actual != checksum:
            raise MigrationError(
                f"migration {migration} was modified after it was applied "
                f"(recorded checksum {checksum[:16]}..., file is {actual[:16]}...). "
                "Migrations are immutable once applied; add a new migration instead."
            )
        if name != migration.name:
            raise MigrationError(
                f"migration {version:04d} was applied as {name!r} but the file is "
                f"named {migration.name!r}. Rename the directory back rather than "
                "renaming a migration."
            )


def _split_statements(script: str) -> list[str]:
    """Split a migration file into individual statements.

    ``executescript`` cannot be used inside a transaction: it issues an
    implicit COMMIT before running, which would defeat the atomicity the
    runner depends on. Statements are therefore executed one at a time.

    ``sqlite3.complete_statement`` is used rather than splitting on ``;``
    because a ``CREATE TRIGGER`` body contains semicolons that are not
    statement terminators.
    """
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        stripped = line.strip()
        # Comments are stripped so a semicolon inside one cannot be mistaken
        # for a terminator, and so a trigger body's internal `;` is judged by
        # SQLite rather than by this loop.
        if not stripped or stripped.startswith("--"):
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    leftover = buffer.strip()
    if leftover:
        # Incomplete but non-empty: the file is truncated or has a syntax
        # error. Reported rather than silently applied as far as it parsed.
        raise MigrationError(
            f"migration file ends mid-statement: {leftover[:120]!r}"
        )
    return statements


def _apply(conn: sqlite3.Connection, migration: Migration) -> None:
    """Apply one migration inside its own transaction.

    The record of the migration is written in the *same* transaction as the
    schema change. If they were separate, a crash between them would leave a
    schema applied but unrecorded, and the next start would try to apply it
    again.
    """
    sql = migration.path.read_text(encoding="utf-8")
    statements = _split_statements(sql)
    if not statements:
        raise MigrationError(f"migration {migration} contains no SQL statements")

    checksum = migration.checksum
    applied_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        raise MigrationError(
            f"cannot begin migration {migration}: {exc}. Another process may be "
            "running the migration; only one instance of ciphermesh-edge may start "
            "at a time."
        ) from exc

    try:
        for statement in statements:
            conn.execute(statement)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at) "
            "VALUES (?, ?, ?, ?)",
            (migration.version, migration.name, checksum, applied_at),
        )
    except sqlite3.Error as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:  # pragma: no cover
            pass
        raise MigrationError(
            f"migration {migration} failed and was rolled back: {exc}"
        ) from exc
    else:
        conn.execute("COMMIT")


def _bootstrap(conn: sqlite3.Connection) -> None:
    """Create the bookkeeping table if it is missing."""
    try:
        conn.executescript(_BOOTSTRAP)
    except sqlite3.Error as exc:
        raise StorageError(f"cannot create schema_migrations: {exc}") from exc


def bootstrap_and_migrate(
    conn: sqlite3.Connection, directory: Path | None = None
) -> list[Migration]:
    """Apply every outstanding migration, bootstrapping bookkeeping first.

    This is the entry point callers should use: it is exactly :func:`migrate`
    under a name that says what it does, kept because a reader who finds
    ``migrate(conn)`` at a call site has to go and check whether it also
    creates the table it records into.
    """
    return migrate(conn, directory)
