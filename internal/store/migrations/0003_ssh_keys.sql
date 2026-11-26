-- A user's SSH public keys. The fingerprint is the key's identity: one key
-- belongs to at most one account, so a key never authenticates as two users.
CREATE TABLE ssh_keys (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    fingerprint TEXT    NOT NULL UNIQUE CHECK (length(fingerprint) BETWEEN 8 AND 100),
    key_type    TEXT    NOT NULL,
    blob        BLOB    NOT NULL CHECK (length(blob) BETWEEN 1 AND 8192),
    comment     TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX ssh_keys_user ON ssh_keys(user_id);

-- Forge-wide settings, one row per name.
CREATE TABLE settings (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
