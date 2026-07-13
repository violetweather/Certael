CREATE TABLE IF NOT EXISTS certael_agent_sessions(
    agent_session_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    player_subject text NOT NULL,
    match_id text NOT NULL,
    build_id text NOT NULL,
    agent_public_key bytea NOT NULL CHECK (octet_length(agent_public_key) = 32),
    last_sequence numeric(20,0) NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_report_digest bytea NOT NULL CHECK (octet_length(last_report_digest) = 32),
    challenge bytea NULL CHECK (challenge IS NULL OR octet_length(challenge) BETWEEN 16 AND 256),
    challenge_expires_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    last_report_at timestamptz NULL,
    revoked_at timestamptz NULL,
    revocation_reason text NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((challenge IS NULL) = (challenge_expires_at IS NULL)),
    CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 512)
);

CREATE INDEX IF NOT EXISTS certael_agent_sessions_tenant
    ON certael_agent_sessions(tenant_id, environment_id, agent_session_id);

CREATE TABLE IF NOT EXISTS certael_agent_reports(
    tenant_id text NOT NULL,
    agent_session_id text NOT NULL REFERENCES certael_agent_sessions(agent_session_id),
    sequence numeric(20,0) NOT NULL CHECK (sequence > 0),
    report_digest bytea NOT NULL CHECK (octet_length(report_digest) = 32),
    canonical_report bytea NOT NULL CHECK (octet_length(canonical_report) BETWEEN 1 AND 65536),
    observed_at timestamptz NOT NULL,
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY(tenant_id, agent_session_id, sequence),
    UNIQUE(tenant_id, agent_session_id, report_digest)
);

CREATE INDEX IF NOT EXISTS certael_agent_reports_retention
    ON certael_agent_reports(tenant_id, accepted_at);

ALTER TABLE certael_agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_agent_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_agent_sessions_tenant ON certael_agent_sessions;
CREATE POLICY certael_agent_sessions_tenant ON certael_agent_sessions
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

ALTER TABLE certael_agent_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_agent_reports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_agent_reports_tenant ON certael_agent_reports;
CREATE POLICY certael_agent_reports_tenant ON certael_agent_reports
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

