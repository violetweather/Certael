ALTER TABLE certael_sessions
    ADD COLUMN IF NOT EXISTS protection_profile_id text NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS protocol_minimum integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS protocol_maximum integer NOT NULL DEFAULT 1;

ALTER TABLE certael_sessions DROP CONSTRAINT IF EXISTS certael_sessions_protocol_range;
ALTER TABLE certael_sessions ADD CONSTRAINT certael_sessions_protocol_range
    CHECK (protocol_minimum > 0 AND protocol_maximum >= protocol_minimum);
