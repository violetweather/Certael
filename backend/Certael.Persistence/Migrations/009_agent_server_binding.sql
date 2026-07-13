ALTER TABLE certael_agent_sessions
    ADD COLUMN IF NOT EXISTS authoritative_server_id text NOT NULL DEFAULT 'legacy';

CREATE INDEX IF NOT EXISTS certael_agent_sessions_server
    ON certael_agent_sessions(tenant_id, environment_id, authoritative_server_id,
        agent_session_id);
