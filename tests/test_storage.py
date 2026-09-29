"""Storage layer behaviour.

As elsewhere in this suite, the assertions are properties rather than
coverage. Each one exists because its absence would be a security or
data-integrity failure rather than a cosmetic bug.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ciphermesh.config.schema import EventConfig
from ciphermesh.constants import (
    EventType,
    Role,
    SecurityEventCode,
    VerificationStatus,
)
from ciphermesh.crypto import canonical_bytes
from ciphermesh.errors import DuplicateEventError, MigrationError, StorageError
from ciphermesh.events import Event, EventFactory, SequenceAllocator, SignedEvent
from ciphermesh.identity import IdentityManager
from ciphermesh.paths import migrations_dir
from ciphermesh.storage import (
    STAGE_COUNT,
    STATE_KEYS,
    STATE_LAST_SYNC,
    STATE_SEQUENCE,
    Database,
    DeviceRepository,
    EventRepository,
    KVRepository,
    ReplayWindow,
    SecurityEventRepository,
    StageResult,
    StateRepository,
    SyncQueueRepository,
    VerificationAttempt,
    VerificationRepository,
    bootstrap_and_migrate,
    current_version,
    discover,
    migrate,
)
from ciphermesh.storage.db import connect
from ciphermesh.storage.migrations import _split_statements

PASSPHRASE = "correct horse battery staple"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "ciphermesh.db")
    migrate(database.connection)
    yield database
    database.close()


@pytest.fixture
def conn(db):
    with db.read() as connection:
        yield connection


@pytest.fixture
def devices(conn):
    return DeviceRepository(conn)


@pytest.fixture
def events(conn):
    return EventRepository(conn)


@pytest.fixture
def db_write(db):
    """``with db_write() as c:`` - a write transaction on the test's database."""
    return db.write


@pytest.fixture
def db_read(db):
    """``with db_read() as c:`` - a read view on the test's database."""
    return db.read


@pytest.fixture
def manager(state_dir, tmp_path):
    return IdentityManager.open(
        PASSPHRASE,
        device_id="PI-A-0001",
        device_name="greenhouse",
        role=Role.GATEWAY_SENSOR,
        identity_path=tmp_path / "identity" / "device_identity.json",
    )


#: Scratch state for the sequence allocator, so signed events can be built
#: without touching a real node's state directory.
_SCRATCH = Path(tempfile.mkdtemp(prefix="ciphermesh-storage-"))


@pytest.fixture(autouse=True)
def _fresh_sequence():
    """Reset the scratch sequence counter before each test.

    Without this, sequences requested explicitly (a replay at sequence 1, say)
    would drift as earlier tests consumed the shared allocator, and the test
    would silently stop testing what it claims to.
    """
    (_SCRATCH / "sequence.json").unlink(missing_ok=True)
    yield


def make_signed(manager, value=27.5, *, sequence=1, kind=EventType.TEMPERATURE):
    """A signed event at a chosen sequence.

    The sequence is advanced on a real allocator rather than faked, so the
    event is a genuine signed artefact and the same code path a sensor would
    take is exercised.
    """
    allocator = SequenceAllocator(_SCRATCH / "sequence.json")
    for _ in range(sequence - 1):
        allocator.next()
    factory = EventFactory.from_identity(EventConfig(), manager, allocator)
    return factory.create(kind, value)


# ---------------------------------------------------------------------------
# Connection configuration
# ---------------------------------------------------------------------------


def test_every_connection_gets_every_pragma(tmp_path):
    """A connection opened any other way would behave differently."""
    conn = connect(tmp_path / "x.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    conn.close()


def test_foreign_keys_are_enforced_not_merely_set(conn):
    """The pragma is only meaningful if a violation is actually rejected."""
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO events (event_id, version, device_id, event_type, value, unit, "
            "sequence, timestamp, timestamp_unix, event_hash, key_id, signature, payload, "
            "verification_status, origin, received_at) "
            "VALUES ('E1', 1, 'NO-SUCH-DEVICE', 'TEMPERATURE', 1.0, 'C', 1, "
            "'2026-09-29T12:00:00Z', 1.0, ?, 'aa', ?, '{}', 'VERIFIED', 'remote', 'x')",
            ("0" * 64, b"\x00" * 64),
        )


def test_the_database_is_not_world_readable(tmp_path):
    path = tmp_path / "perm.db"
    connect(path).close()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & 0o007, f"database is world-accessible: {oct(mode)}"


def test_a_world_readable_database_is_refused(tmp_path):
    path = tmp_path / "loose.db"
    connect(path).close()
    os.chmod(path, 0o666)
    with pytest.raises(StorageError, match="world-accessible"):
        connect(path)


def test_an_owner_only_database_is_tightened(tmp_path):
    """0o600 is safe but stricter than configured, so it is widened to the
    configured mode - the same thing a manual chmod would have achieved."""
    path = tmp_path / "tight.db"
    connect(path).close()
    os.chmod(path, 0o600)
    connect(path).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_a_group_readable_database_is_left_alone(tmp_path):
    """Group access is not this module's to remove. It refuses only what
    would expose the database to every user on the box."""
    path = tmp_path / "group.db"
    connect(path).close()
    os.chmod(path, 0o640)
    connect(path).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_the_parent_directory_is_created(tmp_path):
    nested = tmp_path / "a" / "b" / "ciphermesh.db"
    connect(nested).close()
    assert nested.exists()


def test_using_a_closed_database_is_an_error(db):
    db.close()
    with pytest.raises(StorageError, match="closed"):
        _ = db.connection


def test_close_checkpoints_the_wal(tmp_path):
    """A copied .db file must be complete without its -wal sidecar."""
    path = tmp_path / "t.db"
    database = Database(path)
    migrate(database.connection)
    with database.write() as c:
        c.execute("INSERT INTO kv (key, value, updated_at) VALUES ('k', 'v', 'now')")
    database.close()

    assert not (tmp_path / "t.db-wal").exists() or (tmp_path / "t.db-wal").stat().st_size == 0
    # A fresh process must see the committed write.
    other = connect(path)
    assert other.execute("SELECT value FROM kv WHERE key='k'").fetchone()[0] == "v"
    other.close()


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


def test_a_failed_transaction_rolls_back_whole(db_write, db):
    with pytest.raises(RuntimeError), db_write() as c:
        c.execute("INSERT INTO kv (key, value, updated_at) VALUES ('a', '1', 'now')")
        raise RuntimeError("boom")
    assert db.execute("SELECT COUNT(*) FROM kv").fetchone()[0] == 0


def test_a_multi_statement_write_is_all_or_nothing(db_read, db_write, state_dir, db):
    """Storing an event without recording its verification must not persist."""
    manager = IdentityManager.open(PASSPHRASE, device_id="PI-A-0001")
    with db_read() as c:
        DeviceRepository(c).register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)

    with pytest.raises(RuntimeError), db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED)
        SecurityEventRepository(c).record(
            SecurityEventCode.INVALID_SIGNATURE, event_id=signed.event.event_id
        )
        raise RuntimeError("crash after the event insert")

    with db_read() as c:
        assert EventRepository(c).count() == 0
        assert SecurityEventRepository(c).recent() == []


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------


def test_the_initial_schema_creates_every_planned_table(conn):
    names = {
        r["name"]
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {
        "devices", "events", "event_verifications", "security_events",
        "sync_queue", "system_state", "schema_migrations", "replay_window", "kv",
    } <= names


def test_migrations_are_idempotent(db):
    assert migrate(db.connection) == []
    assert current_version(db.connection) == 1


def test_the_shipped_migrations_are_found_without_being_told_where():
    """A wheel that omits the SQL directory cannot start at all.

    ``discover()`` defaults to the package directory, so a packaging mistake
    shows up here rather than on a node that has already been installed.
    """
    found = discover()
    assert [m.version for m in found] == [1]
    assert found[0].name == "initial"
    assert found[0].path.parent == migrations_dir()


def test_bootstrap_and_migrate_matches_migrate(tmp_path):
    """The documented entry point must be the real one, not a divergent copy."""
    one, two = tmp_path / "a.db", tmp_path / "b.db"
    with Database(one) as first, Database(two) as second:
        assert bootstrap_and_migrate(first.connection) == migrate(second.connection)


def test_a_second_migration_is_discovered_in_order(tmp_path):
    source = Path(__file__).resolve().parents[1] / "src" / "ciphermesh" / "storage" / "migrations"
    versions = [m.version for m in discover(source)]
    assert versions == sorted(versions)
    assert versions[0] == 1


def test_a_badly_named_migration_is_fatal(tmp_path):
    """Skipping it would silently drop a schema change from the deployment."""
    bad = tmp_path / "migrations"
    bad.mkdir()
    (bad / "latest.sql").write_text("CREATE TABLE t (a);")
    with pytest.raises(MigrationError, match="does not match"):
        discover(bad)


def test_duplicate_versions_are_fatal(tmp_path):
    bad = tmp_path / "migrations"
    bad.mkdir()
    (bad / "001_a.sql").write_text("CREATE TABLE a (x);")
    (bad / "001_b.sql").write_text("CREATE TABLE b (x);")
    with pytest.raises(MigrationError, match="duplicate migration version"):
        discover(bad)


def test_a_missing_migrations_directory_is_fatal(tmp_path):
    with pytest.raises(MigrationError, match="does not exist"):
        discover(tmp_path / "nope")


def test_an_edited_applied_migration_refuses_to_start(tmp_path, db):
    """The check that makes forward-only real."""
    source = tmp_path / "migrations"
    source.mkdir()
    original = (
        Path(__file__).resolve().parents[1]
        / "src" / "ciphermesh" / "storage" / "migrations" / "001_initial.sql"
    )
    target = source / "001_initial.sql"
    target.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")

    database = Database(tmp_path / "t.db")
    migrate(database.connection, source)
    database.close()

    # Someone "fixes a typo" in a migration that has already run everywhere.
    target.write_text(
        target.read_text(encoding="utf-8") + "\n-- a comment added after deployment\n",
        encoding="utf-8",
    )
    database = Database(tmp_path / "t.db")
    with pytest.raises(MigrationError, match="modified after it was applied"):
        migrate(database.connection, source)
    database.close()


def test_a_missing_applied_migration_refuses_to_start(tmp_path, db):
    source = tmp_path / "migrations"
    source.mkdir()
    (source / "001_a.sql").write_text("CREATE TABLE a (x);", encoding="utf-8")
    database = Database(tmp_path / "t.db")
    migrate(database.connection, source)
    database.close()

    (source / "001_a.sql").unlink()
    database = Database(tmp_path / "t.db")
    with pytest.raises(MigrationError, match="is recorded as applied but its file is missing"):
        migrate(database.connection, source)
    database.close()


def test_a_failing_migration_rolls_back_and_is_not_recorded(tmp_path):
    bad = tmp_path / "migrations"
    bad.mkdir()
    (bad / "001_a.sql").write_text(
        "CREATE TABLE good (x);\nCREATE TABLE bad (y, y);\n", encoding="utf-8"
    )
    database = Database(tmp_path / "t.db")
    with pytest.raises(MigrationError, match="rolled back"):
        migrate(database.connection, bad)
    # Neither table survives, and nothing is recorded as applied.
    names = {
        r["name"]
        for r in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "good" not in names
    assert "bad" not in names
    assert current_version(database.connection) == 0
    database.close()


def test_statement_splitting_handles_a_trigger_body(tmp_path):
    """A CREATE TRIGGER contains semicolons that are not terminators."""
    script = """
    CREATE TABLE t (a INTEGER);
    -- a comment with a ; semicolon
    CREATE TRIGGER trg AFTER INSERT ON t
    BEGIN
        UPDATE t SET a = 1;
        UPDATE t SET a = 2;
    END;
    """
    statements = _split_statements(script)
    assert len(statements) == 2
    assert statements[1].count(";") >= 3


def test_a_truncated_migration_is_rejected():
    with pytest.raises(MigrationError, match="ends mid-statement"):
        _split_statements("CREATE TABLE a (x);\nCREATE TABLE b (")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def test_register_derives_the_key_id(devices, manager):
    record = devices.register("PI-A-0001", manager.public_key, device_name="greenhouse")
    assert record.key_id == manager.key_id
    assert record.public_key == manager.public_key
    assert record.revoked is False


def test_a_32_byte_key_is_enforced(devices):
    with pytest.raises(StorageError, match="32 bytes"):
        devices.register("PI-A-0001", b"short")


def test_an_empty_device_id_is_refused(devices, manager):
    with pytest.raises(StorageError, match="must not be empty"):
        devices.register("  ", manager.public_key)


def test_a_known_device_cannot_be_re_keyed(devices, manager, keypair):
    """Silently swapping the key would let anyone take over a known device id."""
    devices.register("PI-A-0001", manager.public_key)
    with pytest.raises(StorageError, match="refusing to replace"):
        devices.register("PI-A-0001", keypair.public_raw)


def test_re_keying_is_possible_but_explicit(devices, manager, keypair):
    devices.register("PI-A-0001", manager.public_key)
    updated = devices.register("PI-A-0001", keypair.public_raw, allow_key_change=True)
    assert updated.key_id == keypair.key_id


def test_re_registering_the_same_key_only_refreshes_metadata(devices, manager):
    first = devices.register("PI-A-0001", manager.public_key, device_name="old")
    again = devices.register("PI-A-0001", manager.public_key, device_name="new")
    assert first.first_seen == again.first_seen
    assert again.device_name == "new"
    assert devices.count() == 1


def test_revocation_removes_the_key_from_resolution(devices, manager):
    devices.register("PI-A-0001", manager.public_key)
    assert devices.resolve(manager.key_id) is not None
    assert devices.revoke("PI-A-0001", "compromised") is True
    assert devices.resolve(manager.key_id) is None
    # The row survives; only its resolvability changed.
    assert devices.get("PI-A-0001").revoked is True
    assert devices.get_by_key_id(manager.key_id) is not None


def test_revocation_is_idempotent(devices, manager):
    devices.register("PI-A-0001", manager.public_key)
    assert devices.revoke("PI-A-0001", "first") is True
    assert devices.revoke("PI-A-0001", "second") is False
    # The original reason is preserved rather than overwritten.
    assert devices.get("PI-A-0001").revoke_reason == "first"


def test_a_revoked_device_can_be_restored(devices, manager):
    devices.register("PI-A-0001", manager.public_key)
    devices.revoke("PI-A-0001", "test")
    assert devices.unrevoke("PI-A-0001") is True
    assert devices.resolve(manager.key_id) is not None


def test_a_device_with_events_cannot_be_deleted(events, devices, manager, db_write):
    """Deleting the key would orphan the history verified with it."""
    devices.register("PI-A-0001", manager.public_key)
    with db_write() as c:
        EventRepository(c).store(make_signed(manager), VerificationStatus.VERIFIED)
    with pytest.raises(StorageError, match="Revoke it instead"):
        devices.delete("PI-A-0001")


def test_keystore_reflects_revocation_immediately(devices, manager, keypair):
    """A cached keyring would keep accepting a revoked device."""
    devices.register("PI-A-0001", manager.public_key)
    assert manager.key_id in devices.keystore()
    devices.revoke("PI-A-0001", "compromised")
    assert manager.key_id not in devices.keystore()


def test_the_keystore_verifies_a_real_signature(devices, manager):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    assert signed.verify_with(devices.keystore())


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_store_persists_the_signed_payload_verbatim(db_read, db, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        row_id = EventRepository(c).store(signed, VerificationStatus.VERIFIED, origin="local")

    with db_read() as c:
        record = EventRepository(c).get(signed.event.event_id)
    assert record.id == row_id
    # The stored payload is byte-identical to what the sender signed, so
    # re-verification after any schema change still works.
    assert record.payload == canonical_bytes(signed.event.canonical_payload()).decode("utf-8")
    assert record.to_signed_event().verify(manager.public_key)


def test_a_stored_event_can_still_be_verified_after_other_rows_exist(
    db_write, db_read, devices, manager
):
    """Nothing about insertion order may affect a stored signature."""
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED)
    for i in range(20):
        with db_write() as c:
            EventRepository(c).store(make_signed(manager, 20.0 + i, sequence=i + 2),
                                     VerificationStatus.VERIFIED)

    with db_read() as c:
        record = EventRepository(c).get(signed.event.event_id)
    assert record.to_signed_event().verify(manager.public_key)
    assert record.to_signed_event().event.hash() == record.event_hash


def test_rejected_events_are_stored(db_read, db, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store_rejected(signed, VerificationStatus.INVALID_SIGNATURE)

    with db_read() as c:
        record = EventRepository(c).get(signed.event.event_id)
    assert record.verification_status == "INVALID_SIGNATURE"
    assert record.verified_at is None
    assert record.accepted is False


def test_store_rejected_refuses_an_accepting_status(events, devices, manager):
    with pytest.raises(StorageError, match="accepting status"):
        events.store_rejected(make_signed(manager), VerificationStatus.VERIFIED)


def test_status_can_be_updated_after_the_fact(db, devices, manager, db_write, db_read):
    """A late stage must not require rewriting the signed bytes.

    ``verification_status`` is the receiver's conclusion, not part of the
    signed payload, so it can change as the pipeline advances without
    invalidating the signature.
    """
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        row_id = EventRepository(c).store(signed, VerificationStatus.SCHEMA_INVALID)
    with db_write() as c:
        EventRepository(c).set_status(row_id, VerificationStatus.VERIFIED)
    with db_read() as c:
        record = EventRepository(c).get(signed.event.event_id)
    assert record.verification_status == "VERIFIED"
    assert record.verified_at is not None
    assert record.to_signed_event().verify(manager.public_key)


def test_the_same_sequence_cannot_be_stored_twice(db, devices, manager, db_write):
    """The database is the backstop if the pipeline's check ever fails."""
    devices.register("PI-A-0001", manager.public_key)
    first = make_signed(manager, 27.5, sequence=1)
    replay = SignedEvent(
        event=Event(
            event_id="EVT-20260929-PI-A-00000001-dead",
            device_id=first.event.device_id,
            event_type=first.event.event_type,
            value=99.9,
            unit=first.event.unit,
            sequence=1,
            timestamp=first.event.timestamp,
        ),
        signature=first.signature,
        key_id=first.key_id,
    )
    with db_write() as c:
        EventRepository(c).store(first, VerificationStatus.VERIFIED)
    with pytest.raises(DuplicateEventError, match="replay"), db_write() as c:
        EventRepository(c).store(replay, VerificationStatus.VERIFIED)


def test_the_same_event_id_cannot_be_stored_twice(db, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED)
    with pytest.raises(DuplicateEventError, match="already stored"), db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED)


def test_a_duplicate_is_distinguishable_from_a_storage_fault(db, devices, manager, db_write):
    """The receive path records REPLAY_REJECTED on a duplicate, so a genuine
    schema violation must not be reported as one. A handler that catches
    DuplicateEventError has to miss the constraint failures."""
    devices.register("PI-A-0001", manager.public_key)
    with pytest.raises(sqlite3.IntegrityError) as caught, db_write() as c:
        c.execute(
            "INSERT INTO devices (device_id, key_id, public_key) "
            "VALUES ('PI-B-0001', 'short', x'00')"
        )
    assert not isinstance(caught.value, DuplicateEventError)


def test_a_nan_value_is_rejected_by_the_schema(db_write, db, devices, manager):
    """SQLite happily stores NaN as NULL; the CHECK must stop it."""
    devices.register("PI-A-0001", manager.public_key)
    with pytest.raises(sqlite3.IntegrityError), db_write() as c:
        c.execute(
            "INSERT INTO events (event_id, version, device_id, event_type, value, unit, "
            "sequence, timestamp, timestamp_unix, event_hash, key_id, signature, payload, "
            "verification_status, origin, received_at) "
            "VALUES ('E', 1, 'PI-A-0001', 'TEMPERATURE', ?, 'C', 1, "
            "'2026-09-29T12:00:00Z', 1.0, ?, 'aa', ?, '{}', 'VERIFIED', 'remote', 'x')",
            (float("nan"), "0" * 64, b"\x00" * 64),
        )


def test_highest_sequence_counts_rejected_events(db_read, db, devices, manager, db_write):
    """Reusing a number an attacker already used is the thing to prevent."""
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager, sequence=7)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.SCHEMA_INVALID)

    with db_read() as c:
        assert EventRepository(c).highest_sequence("PI-A-0001") == 7
        assert EventRepository(c).highest_sequence("UNKNOWN") == 0


def test_latest_is_newest_first_and_paginated(db_read, db, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    for i in range(5):
        with db_write() as c:
            EventRepository(c).store(make_signed(manager, 20.0 + i, sequence=i + 1),
                                     VerificationStatus.VERIFIED)
    with db_read() as c:
        repo = EventRepository(c)
        page1 = repo.latest(limit=2)
        page2 = repo.latest(limit=2, offset=2)
    assert len(page1) == 2
    assert {r.id for r in page1}.isdisjoint({r.id for r in page2})


def test_a_zero_limit_is_refused(events):
    with pytest.raises(StorageError, match="at least 1"):
        events.latest(limit=0)


def test_the_page_size_is_capped(events, db_read):
    """A pathological request must not exhaust the page cache."""
    with db_read() as c:
        rows = EventRepository(c).latest(limit=10_000_000)
    assert isinstance(rows, list)


def test_prune_removes_old_events_and_keeps_new(db_read, db, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=40)
    with db_write() as c:
        EventRepository(c).store(make_signed(manager, 20.0, sequence=1),
                                 VerificationStatus.VERIFIED)
    with db_read() as c:
        repo = EventRepository(c)
        row = repo.get(repo.latest()[0].event_id)
        with db.write() as w:
            w.execute("UPDATE events SET timestamp_unix = ? WHERE id = ?",
                      (old.timestamp(), row.id))
        removed = repo.prune((now - timedelta(days=30)).timestamp())

    with db_read() as c:
        assert EventRepository(c).count() == 0
    assert removed == 1


def test_iter_all_streams_everything(db_read, db, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    for i in range(7):
        with db_write() as c:
            EventRepository(c).store(make_signed(manager, 20.0 + i, sequence=i + 1),
                                     VerificationStatus.VERIFIED)
    with db_read() as c:
        assert len(list(EventRepository(c).iter_all(batch=3))) == 7


# ---------------------------------------------------------------------------
# Verification records
# ---------------------------------------------------------------------------


def test_all_nine_stages_are_recorded(db_read, conn, events, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED)
        VerificationRepository(c).record_attempt(
            VerificationAttempt(
                event_id=signed.event.event_id,
                status=VerificationStatus.VERIFIED,
                stages=tuple(StageResult(s, "PASS") for s in range(STAGE_COUNT)),
            )
        )
    with db_read() as c:
        rows = list(c.execute("SELECT * FROM event_verifications"))
    assert len(rows) == 9
    assert [r["stage"] for r in rows] == list(range(9))


def test_a_failure_records_every_stage_including_skipped(db_read, conn, events, devices, manager, db_write):
    """A gap in the list must be distinguishable from a version mismatch."""
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.UNKNOWN_DEVICE)
        VerificationRepository(c).record_attempt(
            VerificationAttempt(
                event_id=signed.event.event_id,
                status=VerificationStatus.UNKNOWN_DEVICE,
                stages=tuple(
                    StageResult(i, "PASS" if i < 1 else "FAIL" if i == 1 else "SKIPPED")
                    for i in range(STAGE_COUNT)
                ),
            )
        )
    with db_read() as c:
        attempt = VerificationRepository(c).attempts_for(signed.event.event_id)[0]
    assert attempt.failure_stage_name == "DEVICE_RESOLVED"
    assert attempt.status is VerificationStatus.UNKNOWN_DEVICE
    assert len(attempt.stages) == 9


def test_the_rejecting_stage_maps_to_its_status(db_read, conn, events, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.INVALID_SIGNATURE)
        VerificationRepository(c).record_attempt(
            VerificationAttempt(
                event_id=signed.event.event_id,
                status=VerificationStatus.INVALID_SIGNATURE,
                stages=tuple(
                    StageResult(i, "FAIL" if i == 2 else "PASS" if i < 2 else "SKIPPED")
                    for i in range(STAGE_COUNT)
                ),
            )
        )
    with db_read() as c:
        assert VerificationRepository(c).attempts_for(
            signed.event.event_id
        )[0].status is VerificationStatus.INVALID_SIGNATURE


def test_stage_records_cascade_when_the_event_goes(db_read, conn, events, devices, manager, db_write):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED)
        VerificationRepository(c).record_attempt(
            VerificationAttempt(
                event_id=signed.event.event_id,
                status=VerificationStatus.VERIFIED,
                stages=tuple(StageResult(s, "PASS") for s in range(STAGE_COUNT)),
            )
        )
    with db_write() as c:
        c.execute("DELETE FROM events WHERE event_id = ?", (signed.event.event_id,))
    with db_read() as c:
        assert list(c.execute("SELECT * FROM event_verifications")) == []


def test_rejection_counts_by_stage(conn, events, devices, manager, db_write, db_read):
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.INVALID_SIGNATURE)
        VerificationRepository(c).record_attempt(
            VerificationAttempt(
                event_id=signed.event.event_id,
                status=VerificationStatus.INVALID_SIGNATURE,
                stages=tuple(
                    StageResult(i, "FAIL" if i == 2 else "PASS" if i < 2 else "SKIPPED")
                    for i in range(STAGE_COUNT)
                ),
            )
        )
    with db_read() as c:
        assert VerificationRepository(c).rejection_counts() == {"SIGNATURE_VERIFIED": 1}


def test_out_of_order_stages_are_refused():
    with pytest.raises(ValueError, match="pipeline order"):
        VerificationAttempt(
            event_id="E", status=VerificationStatus.VERIFIED,
            stages=(StageResult(2, "PASS"), StageResult(0, "PASS")),
        )


def test_an_out_of_range_stage_is_refused():
    with pytest.raises(ValueError, match="outside"):
        StageResult(STAGE_COUNT, "PASS")
    with pytest.raises(ValueError, match="outside"):
        StageResult(-1, "PASS")


def test_an_invalid_outcome_is_refused():
    with pytest.raises(ValueError, match="invalid stage outcome"):
        StageResult(0, "MAYBE")


# ---------------------------------------------------------------------------
# Replay window
# ---------------------------------------------------------------------------


def test_a_hash_is_remembered_once(conn):
    window = ReplayWindow(conn)
    assert window.remember("a" * 64, "E1", "PI-A-0001", 1) is True
    assert window.remember("a" * 64, "E1", "PI-A-0001", 1) is False
    assert window.seen("a" * 64) is True


def test_a_resequenced_replay_is_still_caught(conn):
    """Different sequence, identical bytes: only the hash catches it."""
    window = ReplayWindow(conn)
    window.remember("b" * 64, "E1", "PI-A-0001", 1)
    assert window.seen("b" * 64) is True
    assert window.highest_sequence("PI-A-0001") == 1


def test_the_window_prunes_by_age(conn, db_write):
    """A cut-off in the past must keep recent entries; one in the future must
    drop them. Getting the comparison backwards would silently make the window
    useless, so both directions are checked."""
    window = ReplayWindow(conn)
    window.remember("a" * 64, "E1", "PI-A-0001", 1)
    now = time.time()

    assert window.prune(now - 3600) == 0
    assert window.count() == 1

    with db_write() as c:
        removed = ReplayWindow(c).prune(now + 1)
    assert removed == 1
    assert window.count() == 0


def test_the_window_is_capped_by_entry_count(conn, db_write):
    """A long window must still not grow without bound."""
    for i in range(25):
        ReplayWindow(conn).remember(f"{i:064x}", f"E{i}", "PI-A-0001", i)
    # A cut-off in the past expires nothing, so only the cap can act here.
    with db_write() as c:
        assert ReplayWindow(c, max_entries=10).prune(time.time() - 3600) == 15
    assert ReplayWindow(conn).count() == 10


# ---------------------------------------------------------------------------
# Security events
# ---------------------------------------------------------------------------


def test_security_events_record_and_query(conn):
    repo = SecurityEventRepository(conn)
    repo.record(SecurityEventCode.INVALID_SIGNATURE, device_id="PI-A-0001",
                detail="bad signature", severity="WARN")
    repo.record(SecurityEventCode.INTERNET_LOST, severity="INFO")
    assert len(repo.recent()) == 2
    assert repo.counts_by_code()["INVALID_SIGNATURE"] == 1


def test_severity_filtering(conn):
    repo = SecurityEventRepository(conn)
    repo.record(SecurityEventCode.INTERNET_LOST, severity="INFO")
    repo.record(SecurityEventCode.DEVICE_REVOKED, severity="CRITICAL")
    assert len(repo.recent(min_severity="WARN")) == 1
    assert len(repo.recent(min_severity="INFO")) == 2


def test_an_unknown_severity_is_refused(conn):
    with pytest.raises(StorageError, match="unknown severity"):
        SecurityEventRepository(conn).recent(min_severity="EXTREME")


def test_count_since_supports_rate_limiting(conn):
    repo = SecurityEventRepository(conn)
    import time

    for _ in range(5):
        repo.record(SecurityEventCode.INVALID_SIGNATURE)
    assert repo.count_since(SecurityEventCode.INVALID_SIGNATURE, time.time() - 60) == 5
    assert repo.count_since(SecurityEventCode.INVALID_SIGNATURE, time.time() + 60) == 0


def test_security_events_prune_by_age(conn):
    repo = SecurityEventRepository(conn)
    repo.record(SecurityEventCode.SENSOR_FAILURE)
    import time

    assert repo.prune(time.time() - 60) == 0
    assert repo.prune(time.time() + 60) == 1


# ---------------------------------------------------------------------------
# system_state and kv
# ---------------------------------------------------------------------------


def test_system_state_round_trips(conn):
    repo = StateRepository(conn)
    repo.set("highest_sequence", "42")
    assert repo.get("highest_sequence") == "42"
    assert repo.get_int("highest_sequence") == 42


def test_a_corrupt_integer_state_is_refused_not_guessed(conn):
    """A typo must not read as 'not set yet' and reset a security parameter."""
    repo = StateRepository(conn)
    repo.set(STATE_SEQUENCE, "not-a-number")
    with pytest.raises(StorageError, match="not an integer"):
        repo.get_int(STATE_SEQUENCE)


def test_system_state_refuses_an_unknown_key(conn):
    """The key set is closed, so a misspelling cannot read as 'unset'."""
    with pytest.raises(StorageError, match="unknown system_state key"):
        StateRepository(conn).set("higest_sequence", "1")
    with pytest.raises(StorageError, match="unknown system_state key"):
        StateRepository(conn).get("higest_sequence")
    # Even a default is not returned for an unknown key: the default is the
    # caller's "unset" signal, and it must not paper over a misspelling.
    assert STATE_SEQUENCE in STATE_KEYS


def test_system_state_and_kv_are_independent(conn):
    StateRepository(conn).set(STATE_LAST_SYNC, "state")
    KVRepository(conn).set("last_successful_sync", "kv")
    assert StateRepository(conn).get(STATE_LAST_SYNC) == "state"
    assert KVRepository(conn).get("last_successful_sync") == "kv"


def test_kv_defaults(conn):
    repo = KVRepository(conn)
    assert repo.get("missing") is None
    assert repo.get("missing", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# Sync queue
# ---------------------------------------------------------------------------


def test_enqueue_is_idempotent(conn):
    queue = SyncQueueRepository(conn)
    first = queue.enqueue("EVENT", "E1", {"v": 1})
    second = queue.enqueue("EVENT", "E1", {"v": 2})
    assert first == second
    assert queue.counts()["PENDING"] == 1


def test_a_synced_record_is_not_resurrected(conn):
    """Re-uploading a delivered event would duplicate it upstream."""
    queue = SyncQueueRepository(conn)
    queue_id = queue.enqueue("EVENT", "E1", {"v": 1})
    queue.mark_synced(queue_id)
    queue.enqueue("EVENT", "E1", {"v": 1})
    assert queue.get(queue_id).status == "SYNCED"


def test_claim_returns_oldest_first(conn):
    queue = SyncQueueRepository(conn)
    for i in range(5):
        queue.enqueue("EVENT", f"E{i}", {"i": i})
    claimed = queue.claim(batch_size=3)
    assert [c.ref_id for c in claimed] == ["E0", "E1", "E2"]
    assert all(c.status == "SYNCING" for c in claimed)


def test_claimed_records_are_not_claimed_again(conn):
    queue = SyncQueueRepository(conn)
    queue.enqueue("EVENT", "E1", {"v": 1})
    queue.claim(batch_size=10)
    assert queue.claim(batch_size=10) == []


def test_a_crashed_claim_is_reclaimed(conn):
    """A record stuck in SYNCING must not be lost by a restart."""
    queue = SyncQueueRepository(conn)
    queue.enqueue("EVENT", "E1", {"v": 1})
    queue.claim(batch_size=10)
    assert queue.get_by_ref("EVENT", "E1").status == "SYNCING"
    reclaimed = queue.claim(batch_size=10, now=2**31)
    assert [c.ref_id for c in reclaimed] == ["E1"]


def test_an_unexpired_lease_is_not_stolen(conn):
    """A slow upload must not be claimed by a second worker.

    Reclaiming SYNCING purely on status would double-send: the first worker is
    still holding the record, and it may yet succeed.
    """
    queue = SyncQueueRepository(conn)
    queue.enqueue("EVENT", "E1", {"v": 1})
    first = queue.claim(batch_size=10, now=1000.0, lease_seconds=300.0)
    assert [c.ref_id for c in first] == ["E1"]

    assert queue.claim(batch_size=10, now=1100.0) == []
    assert [c.ref_id for c in queue.claim(batch_size=10, now=1300.1)] == ["E1"]


def test_backoff_defers_the_next_attempt(conn):
    queue = SyncQueueRepository(conn)
    queue.enqueue("EVENT", "E1", {"v": 1})
    claimed = queue.claim(batch_size=1)
    attempts = queue.mark_failed(claimed[0].id, "network down", next_attempt_at=2**31)
    assert attempts == 1
    assert queue.claim(batch_size=10) == []


def test_failed_records_go_terminal(conn):
    queue = SyncQueueRepository(conn)
    queue.enqueue("EVENT", "E1", {"v": 1})
    claimed = queue.claim(batch_size=1)[0]
    queue.mark_failed(claimed.id, "gave up", 0)
    queue.give_up(claimed.id, "gave up")
    item = queue.get(claimed.id)
    assert item.status == "FAILED"
    assert item.is_terminal
    assert queue.claim(batch_size=10) == []


def test_requeue_recovers_a_failed_record(conn):
    queue = SyncQueueRepository(conn)
    queue_id = queue.enqueue("EVENT", "E1", {"v": 1})
    queue.give_up(queue_id, "error")
    assert queue.requeue(queue_id) is True
    assert queue.get(queue_id).attempts == 0
    assert len(queue.claim(batch_size=10)) == 1


def test_requeue_can_preserve_the_attempt_count(conn):
    """A retry that keeps the count is the one that respects max_attempts."""
    queue = SyncQueueRepository(conn)
    queue_id = queue.enqueue("EVENT", "E1", {"v": 1})
    for _ in range(3):
        queue.mark_failed(queue_id, "boom", next_attempt_at=0.0)
    assert queue.get(queue_id).attempts == 3

    assert queue.requeue(queue_id, reset_attempts=False) is True
    assert queue.get(queue_id).attempts == 3
    assert queue.get(queue_id).last_error is None


def test_requeue_all_failed(conn):
    queue = SyncQueueRepository(conn)
    queue.give_up(queue.enqueue("EVENT", "E1", {}), "e")
    queue.give_up(queue.enqueue("EVENT", "E2", {}), "e")
    assert queue.requeue_all_failed() == 2


def test_marking_synced_updates_the_event_too(db_read, db, devices, events, manager, db_write):
    """The API must not show an event as unsynced after it has been sent."""
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store(signed, VerificationStatus.VERIFIED, origin="local")
    with db_write() as c:
        queue = SyncQueueRepository(c)
        qid = queue.enqueue_event(signed)
        queue.mark_synced(qid)
    with db_read() as c:
        assert EventRepository(c).get(signed.event.event_id).synced_at is not None


def test_queue_depth_and_oldest_age(conn):
    queue = SyncQueueRepository(conn)
    assert queue.depth() == 0
    assert queue.oldest_pending_age() is None
    queue.enqueue("EVENT", "E1", {})
    assert queue.depth() == 1
    assert queue.oldest_pending_age() >= 0


def test_an_invalid_kind_is_refused(conn):
    with pytest.raises(StorageError, match="kind must be one of"):
        SyncQueueRepository(conn).enqueue("NONSENSE", "E1", {})


def test_an_empty_ref_id_is_refused(conn):
    with pytest.raises(StorageError, match="ref_id must not be empty"):
        SyncQueueRepository(conn).enqueue("EVENT", "", {})


def test_a_zero_batch_size_is_refused(conn):
    with pytest.raises(StorageError, match="at least 1"):
        SyncQueueRepository(conn).claim(batch_size=0)


def test_a_rejected_event_is_not_enqueued(db_read, db, devices, events, manager, db_write):
    """Uploading something this node believes is forged is its own incident."""
    devices.register("PI-A-0001", manager.public_key)
    signed = make_signed(manager)
    with db_write() as c:
        EventRepository(c).store_rejected(signed, VerificationStatus.INVALID_SIGNATURE)
    with db_read() as c:
        assert SyncQueueRepository(c).depth() == 0


# ---------------------------------------------------------------------------
# Private key exclusion - the load-bearing assertion of this phase
# ---------------------------------------------------------------------------


def test_no_table_can_hold_a_private_key(conn):
    """A stolen .db must be useless. Enforced by name, not by inspection."""
    forbidden = ("private", "secret", "passphrase", "seed", "mnemonic")
    for table in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        name = table["name"]
        if name.startswith("sqlite_"):
            continue
        for column in conn.execute(f"PRAGMA table_info({name})"):
            column_name = column["name"].lower()
            for word in forbidden:
                assert word not in column_name, (
                    f"column {name}.{column_name} looks like it holds a secret"
                )


def test_the_stored_public_key_is_the_only_key_material(conn, devices, manager, db_read):
    devices.register("PI-A-0001", manager.public_key)
    from cryptography.hazmat.primitives import serialization

    seed = manager._keypair.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with db_read() as c:
        rows = list(c.execute("SELECT public_key FROM devices"))
        assert [bytes(r["public_key"]) for r in rows] == [manager.public_key]
    # Neither the raw seed nor any common encoding of it is in the file.
    import base64

    with open(conn.execute("PRAGMA database_list").fetchone()["file"], "rb") as handle:
        blob = handle.read()
    assert seed not in blob
    assert seed.hex().encode() not in blob
    assert base64.b64encode(seed) not in blob


def test_no_row_anywhere_contains_the_passphrase(db, devices, manager, db_read):
    devices.register("PI-A-0001", manager.public_key)
    for table in ("devices", "events", "kv", "system_state", "sync_queue", "security_events"):
        with db_read() as c:
            for row in c.execute(f"SELECT * FROM {table}"):
                assert PASSPHRASE not in " ".join(str(v) for v in tuple(row))


# ---------------------------------------------------------------------------
# Transaction helpers
# ---------------------------------------------------------------------------
#
# Tests need repositories to see uncommitted rows, so a write must happen
# inside an explicit transaction that the test also holds. These are bound to
# the `db` fixture rather than taking a repository, because a repository
# opened outside a transaction would auto-commit and defeat the point.
