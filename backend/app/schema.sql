-- SecureChat relay schema (version 1).
-- Design rule: this database holds ONLY public key material, password
-- verifiers, session-token hashes, and opaque ciphertext envelopes.
-- There is deliberately no column for message plaintext or private keys.
-- Timestamps are Unix epoch seconds (UTC).

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY CHECK (length(id) = 36),          -- server-generated UUID
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE
                  CHECK (length(username) BETWEEN 3 AND 32),
    display_name  TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    password_hash TEXT NOT NULL,                                     -- scrypt verifier string
    created_at    INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
);

-- Only a hash of the bearer token is stored, so a database leak does not
-- hand out usable sessions.
CREATE TABLE IF NOT EXISTS auth_sessions (
    id         TEXT PRIMARY KEY CHECK (length(id) = 36),
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON auth_sessions(expires_at);

-- Current PUBLIC identity key and signed prekey per user (Stage 3).
CREATE TABLE IF NOT EXISTS identity_keys (
    user_id                 TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    registration_id         INTEGER NOT NULL,
    identity_public         TEXT NOT NULL,
    signed_prekey_id        INTEGER NOT NULL,
    signed_prekey_public    TEXT NOT NULL,
    signed_prekey_signature TEXT NOT NULL,
    key_version             INTEGER NOT NULL DEFAULT 1,
    updated_at              INTEGER NOT NULL
);

-- Append-only record of identity keys, so clients can detect key changes.
CREATE TABLE IF NOT EXISTS identity_key_history (
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_version     INTEGER NOT NULL,
    identity_public TEXT NOT NULL,
    recorded_at     INTEGER NOT NULL,
    PRIMARY KEY (user_id, key_version)
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    consumed_at INTEGER,
    PRIMARY KEY (user_id, key_id)
);

-- Offline queue / delivery state. `envelope` is an opaque, versioned,
-- base64 ciphertext envelope produced by the client. Rows are deleted after
-- acknowledged delivery or on expiry (see docs/database-schema.md).
CREATE TABLE IF NOT EXISTS messages (
    id           TEXT NOT NULL CHECK (length(id) = 36),              -- client-generated UUID (dedup key)
    sender_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    envelope     TEXT NOT NULL CHECK (length(envelope) BETWEEN 1 AND 131072),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    delivered_at INTEGER,
    PRIMARY KEY (sender_id, id)
);
CREATE INDEX IF NOT EXISTS idx_messages_pending
    ON messages(recipient_id, delivered_at, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages(expires_at);
