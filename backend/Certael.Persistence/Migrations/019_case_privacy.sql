ALTER TABLE certael_cases
    ADD COLUMN IF NOT EXISTS privacy_redacted_at timestamptz NULL;

CREATE INDEX IF NOT EXISTS certael_cases_privacy_redaction
    ON certael_cases (tenant_id, environment_id, privacy_redacted_at)
    WHERE privacy_redacted_at IS NOT NULL;

CREATE OR REPLACE FUNCTION certael_reject_append_only_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('certael.privacy_redaction', true) = 'on' THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    RAISE EXCEPTION 'append-only record cannot be changed' USING ERRCODE = '55000';
END
$$;
