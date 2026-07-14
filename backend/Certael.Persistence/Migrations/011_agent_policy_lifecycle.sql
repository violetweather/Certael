CREATE TABLE IF NOT EXISTS certael_agent_policies(
    tenant_id text NOT NULL,
    policy_id text NOT NULL,
    protocol_version integer NOT NULL CHECK (protocol_version = 1),
    game_id text NOT NULL,
    environment_id text NOT NULL,
    requirement_mode integer NOT NULL CHECK (requirement_mode BETWEEN 0 AND 2),
    heartbeat_seconds integer NOT NULL CHECK (heartbeat_seconds BETWEEN 5 AND 300),
    report_seconds integer NOT NULL CHECK (report_seconds BETWEEN 15 AND 3600),
    disconnect_grace_seconds integer NOT NULL CHECK (disconnect_grace_seconds BETWEEN 0 AND 300),
    minimum_agent_version text NOT NULL,
    expires_at timestamptz NOT NULL,
    signed_claims bytea NOT NULL CHECK (octet_length(signed_claims) BETWEEN 1 AND 65536),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    signing_key_id text NOT NULL,
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    stage integer NOT NULL CHECK (stage BETWEEN 0 AND 4),
    canary_percentage integer NOT NULL DEFAULT 0 CHECK (canary_percentage BETWEEN 0 AND 99),
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL,
    PRIMARY KEY(tenant_id, policy_id),
    UNIQUE(tenant_id, policy_digest),
    CHECK ((stage = 2 AND canary_percentage BETWEEN 1 AND 99)
        OR (stage <> 2 AND canary_percentage = 0))
);

CREATE TABLE IF NOT EXISTS certael_agent_policy_approvals(
    tenant_id text NOT NULL,
    policy_id text NOT NULL,
    approver_subject text NOT NULL,
    approved_at timestamptz NOT NULL,
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    PRIMARY KEY(tenant_id, policy_id, approver_subject),
    FOREIGN KEY(tenant_id, policy_id)
        REFERENCES certael_agent_policies(tenant_id, policy_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS certael_agent_policies_resolution
    ON certael_agent_policies(tenant_id, game_id, environment_id, policy_id, stage, expires_at);

ALTER TABLE certael_agent_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_agent_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_agent_policies_tenant ON certael_agent_policies;
CREATE POLICY certael_agent_policies_tenant ON certael_agent_policies
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

ALTER TABLE certael_agent_policy_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_agent_policy_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_agent_policy_approvals_tenant ON certael_agent_policy_approvals;
CREATE POLICY certael_agent_policy_approvals_tenant ON certael_agent_policy_approvals
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
