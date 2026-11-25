-- An administrative act now leaves two rows: 'attempt' when the signed call is
-- authorized, then 'success' or 'failure' once the action has run. Rows written
-- before this migration are attempts, which is all they ever recorded.
ALTER TABLE admin_audit ADD COLUMN outcome TEXT NOT NULL DEFAULT 'attempt'
    CHECK (outcome IN ('attempt', 'success', 'failure'));
