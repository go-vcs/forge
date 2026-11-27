-- The forge's single registration at the identity bridge. secret_sealed is
-- AES-256-GCM ciphertext (internal/secretbox), never the secret itself.
CREATE TABLE oidc_client (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    issuer        TEXT    NOT NULL,
    client_id     TEXT    NOT NULL,
    redirect_uri  TEXT    NOT NULL,
    secret_sealed BLOB,
    updated_at    INTEGER NOT NULL
) STRICT;
