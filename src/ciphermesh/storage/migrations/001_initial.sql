-- 001_initial.sql
--
-- The complete initial schema for CipherMesh Edge.
--
-- Two rules govern this file and every migration that follows it:
--
--   1. NO PRIVATE KEY MATERIAL. The Ed25519 seed lives only in
--      /var/lib/ciphermesh/identity/device_identity.json, derived from an
--      operator passphrase. Nothing in this database may hold a secret that
--      can sign. A stolen .db file must be useless to an attacker. Tests in
--      test_storage.py assert this by name, not just by inspection.
--
--   2. Forward-only. Migrations are applied once and never edited; the
--      runner records a SHA-256 of each file and refuses to start if a file
--      changed after being applied. To change the schema, add 002_*.sql.

-- ---------------------------------------------------------------------------
-- Migration bookkeeping
-- ---------------------------------------------------------------------------
-- Created outside the migration runner, because the runner needs it to exist
-- before it can record anything.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    checksum    TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- devices
-- ---------------------------------------------------------------------------
-- The keyring, persisted so that a PI-B restart does not lose the ability to
-- verify PI-A, and so revocation survives a reboot.
--
-- `public_key` is 32 raw Ed25519 bytes. `key_id` is the first 8 bytes of
-- SHA-256 over it, hex encoded: the identifier that travels on the wire.
-- Both are stored; the redundancy is deliberate. A receiver that resolved a
-- key by recomputing the hash on every packet would have to trust its own
-- SHA-256 on a hot path, and a mismatch between the two is a detectable
-- corruption rather than a silent wrong-key verification.

CREATE TABLE devices (
    device_id      TEXT    PRIMARY KEY,
    device_name    TEXT    NOT NULL DEFAULT '',
    role           TEXT,
    public_key     BLOB    NOT NULL,
    key_id         TEXT    NOT NULL,
    location       TEXT,

    -- Local bookkeeping.
    is_local       INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    first_seen     TEXT    NOT NULL,
    last_seen      TEXT    NOT NULL,
    revoked        INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    revoked_at     TEXT,
    revoke_reason  TEXT,

    -- Length guards. A key_id is 16 hex chars and a public key is 32 bytes;
    -- enforcing that in the schema means a corrupted row cannot reach the
    -- verifier and waste a signature check, or worse, match a prefix.
    CHECK (length(public_key) = 32),
    CHECK (length(key_id) = 16),
    CHECK (revoked = 0 OR revoked_at IS NOT NULL)
);

-- The keyring lookup. Revocation is a column, not a row, so that revoking a
-- device cannot fail because a separate table is unavailable.
CREATE INDEX idx_devices_key_id ON devices(key_id);

-- ---------------------------------------------------------------------------
-- events
-- ---------------------------------------------------------------------------
-- Every event this node has seen, verified or not. Rejected events are stored
-- too: a receiver that discards what it rejects cannot show an operator what
-- was trying to impersonate it.
--
-- `payload` is the exact canonical JSON that was signed, byte for byte. It is
-- stored rather than reconstructed from the columns because the signature is
-- over the canonical form, and re-serializing after a schema change would
-- produce a different message and invalidate every historical signature.
-- Re-verification reads this column and nothing else.

CREATE TABLE events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identity, exactly as signed.
    event_id            TEXT    NOT NULL UNIQUE,
    version             INTEGER NOT NULL DEFAULT 1,
    device_id           TEXT    NOT NULL REFERENCES devices(device_id),
    event_type          TEXT    NOT NULL,
    device_name         TEXT,
    location            TEXT,

    -- Measurement.
    value               REAL    NOT NULL,
    unit                TEXT    NOT NULL,
    sequence            INTEGER NOT NULL,
    -- Both forms are stored: the signed ISO-8601 string and an integer for
    -- range queries. Ordering and windowing must not require parsing text.
    timestamp           TEXT    NOT NULL,
    timestamp_unix      REAL    NOT NULL,

    -- Cryptographic material. All public.
    event_hash          TEXT    NOT NULL,
    key_id              TEXT    NOT NULL,
    signature           BLOB    NOT NULL,
    payload             TEXT    NOT NULL,

    -- Pipeline outcome. Not part of the signature: this is what the *receiver*
    -- concluded, so it must not be inside the bytes it judged.
    verification_status TEXT    NOT NULL,
    verified_at         TEXT,

    -- Provenance.
    origin              TEXT    NOT NULL CHECK (origin IN ('local', 'remote')),
    received_at         TEXT    NOT NULL,
    sent_at             TEXT,

    -- Sync bookkeeping.
    synced_at           TEXT,

    CHECK (length(event_hash) = 64),
    CHECK (length(signature) = 64),
    CHECK (length(key_id) = 16),
    CHECK (value = value),          -- rejects NaN
    CHECK (sequence >= 0)
);

-- Duplicate suppression. A device cannot legitimately originate two events
-- with the same sequence; that is a replay, and the constraint makes the
-- database the last line of defence rather than only the pipeline.
CREATE UNIQUE INDEX idx_events_device_sequence ON events(device_id, sequence);

-- The receiver's hot path: "have I already accepted an event from this device
-- with this or a higher sequence?"
CREATE INDEX idx_events_device_seq_desc ON events(device_id, sequence DESC);

-- Retention sweeps and the monitoring API's time-range queries.
CREATE INDEX idx_events_timestamp ON events(timestamp_unix);

-- The sync queue's claim query.
CREATE INDEX idx_events_unsynced ON events(synced_at) WHERE synced_at IS NULL;

-- ---------------------------------------------------------------------------
-- event_verifications
-- ---------------------------------------------------------------------------
-- One row per verification stage, per attempt. The plan records all nine
-- stages rather than stopping at the first failure, because "it failed at
-- SIGNATURE_VERIFIED" and "it failed at UNKNOWN_DEVICE and never got that far"
-- are different operational problems.
--
-- A stage that did not run is recorded with outcome 'SKIPPED' and a null
-- detail, so the record is complete rather than short. A gap in the stage
-- list would be indistinguishable from a version mismatch.

CREATE TABLE event_verifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT    NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    attempt       INTEGER NOT NULL DEFAULT 1,

    -- Stage ordinal, matching verification/pipeline.py. Stored as an integer
    -- so the recorded order is enforceable, not merely conventional.
    stage         INTEGER NOT NULL,
    stage_name    TEXT    NOT NULL,

    -- PASS | FAIL | SKIPPED
    outcome       TEXT    NOT NULL CHECK (outcome IN ('PASS', 'FAIL', 'SKIPPED')),
    detail        TEXT,
    duration_us   INTEGER,

    recorded_at   TEXT    NOT NULL,

    UNIQUE (event_id, attempt, stage)
);

CREATE INDEX idx_verifications_event ON event_verifications(event_id, attempt);

-- ---------------------------------------------------------------------------
-- replay_window
-- ---------------------------------------------------------------------------
-- Hashes of events accepted within security.replay_window_seconds, used for
-- duplicate detection independently of the sequence check.
--
-- Kept separate from `events` because it is pruned on a rolling time window
-- while events follow retention policy, and because the two answer different
-- questions: `events` answers "what did I receive", this answers "have I seen
-- this exact event before".

CREATE TABLE replay_window (
    event_hash     TEXT    PRIMARY KEY,
    event_id       TEXT    NOT NULL,
    device_id      TEXT    NOT NULL,
    sequence       INTEGER NOT NULL,
    first_seen_at  REAL    NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_replay_seen ON replay_window(first_seen_at);
CREATE INDEX idx_replay_device_seq ON replay_window(device_id, sequence);

-- ---------------------------------------------------------------------------
-- security_events
-- ---------------------------------------------------------------------------
-- The audit trail. Append-only by convention; nothing in the application
-- updates or deletes these except retention pruning.

CREATE TABLE security_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    code           TEXT    NOT NULL,
    -- INFO | WARN | CRITICAL
    severity       TEXT    NOT NULL DEFAULT 'WARN'
                   CHECK (severity IN ('INFO', 'WARN', 'CRITICAL')),
    device_id      TEXT,
    event_id       TEXT,
    detail         TEXT,
    remote_address TEXT,
    occurred_at    TEXT    NOT NULL,
    occurred_unix  REAL    NOT NULL
);

CREATE INDEX idx_security_occurred ON security_events(occurred_unix);
CREATE INDEX idx_security_code ON security_events(code, occurred_unix);

-- ---------------------------------------------------------------------------
-- sync_queue
-- ---------------------------------------------------------------------------
-- Records awaiting upload. `payload` is the JSON body to POST, captured at
-- enqueue time so a sync does not have to re-serialise an event that may
-- since been pruned.
--
-- A unique index on (kind, ref_id) makes enqueue idempotent: re-queueing an
-- event that is already pending updates the existing row instead of sending
-- the same thing twice.

CREATE TABLE sync_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- EVENT | REGISTRATION | SECURITY_EVENT
    kind            TEXT    NOT NULL
                    CHECK (kind IN ('EVENT', 'REGISTRATION', 'SECURITY_EVENT')),
    ref_id          TEXT    NOT NULL,
    payload         TEXT    NOT NULL,

    -- PENDING | SYNCING | SYNCED | FAILED
    status          TEXT    NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'SYNCING', 'SYNCED', 'FAILED')),

    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL    NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    synced_at       TEXT,

    UNIQUE (kind, ref_id)
);

-- The claim query: oldest eligible pending record, in batches.
CREATE INDEX idx_sync_claim ON sync_queue(status, next_attempt_at);

-- ---------------------------------------------------------------------------
-- system_state
-- ---------------------------------------------------------------------------
-- Small key/value state the node must remember across restarts. Separate from
-- `kv` because these keys are load-bearing: a corrupt or missing
-- highest_sequence would weaken replay protection, so this table is
-- restricted to a known set of keys and validated on read.

CREATE TABLE system_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) WITHOUT ROWID;

-- ---------------------------------------------------------------------------
-- kv
-- ---------------------------------------------------------------------------
-- General scratch space: cached sensor state, last cloud ETag, UI
-- preferences. Not trusted, not security-relevant, safe to lose.

CREATE TABLE kv (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) WITHOUT ROWID;
