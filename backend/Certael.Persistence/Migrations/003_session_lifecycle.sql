ALTER TABLE certael_sessions
    ADD COLUMN IF NOT EXISTS absolute_expires_at timestamptz NULL,
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz NULL,
    ADD COLUMN IF NOT EXISTS signing_key_id text NOT NULL DEFAULT 'legacy';

CREATE INDEX IF NOT EXISTS certael_sessions_active
    ON certael_sessions (tenant_id, environment_id, expires_at)
    WHERE revoked_at IS NULL;
