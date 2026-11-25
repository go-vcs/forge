CREATE TABLE admin_credentials (
    id            INTEGER PRIMARY KEY,
    credential_id BLOB    NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 1 AND 1024),
    public_key    BLOB    NOT NULL CHECK (length(public_key) = 65),
    aaguid        TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    created_at    INTEGER NOT NULL,
    revoked_at    INTEGER
) STRICT;

CREATE TABLE users (
    id           INTEGER PRIMARY KEY,
    login        TEXT    NOT NULL UNIQUE,
    display_name TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    disabled_at  INTEGER
) STRICT;

-- An external identity is keyed on (issuer, subject). There is no e-mail column.
CREATE TABLE identities (
    issuer     TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, subject)
) STRICT;

CREATE INDEX identities_user ON identities(user_id);

-- One row per accepted administrative act.
CREATE TABLE admin_audit (
    id            INTEGER PRIMARY KEY,
    at            INTEGER NOT NULL,
    credential_id BLOB,
    method        TEXT    NOT NULL,
    request_sha256 BLOB   NOT NULL
) STRICT;
