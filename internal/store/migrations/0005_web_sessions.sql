-- Server-side web sessions. The cookie carries a random id; only its SHA-256
-- is stored, so a copy of the database signs nobody in. A session names the
-- identity it was created from: unbinding that identity or disabling the
-- account ends it.
CREATE TABLE web_sessions (
    id_hash    BLOB    PRIMARY KEY CHECK (length(id_hash) = 32),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    issuer     TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    csrf       TEXT    NOT NULL CHECK (length(csrf) BETWEEN 16 AND 128),
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
) STRICT;

CREATE INDEX web_sessions_user ON web_sessions(user_id);
CREATE INDEX web_sessions_identity ON web_sessions(issuer, subject);
