ALTER TABLE certael_agent_reports
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;

UPDATE certael_agent_reports
SET expires_at = accepted_at + interval '24 hours'
WHERE expires_at IS NULL;

ALTER TABLE certael_agent_reports
    ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS certael_agent_reports_expiry
    ON certael_agent_reports(tenant_id, expires_at);
