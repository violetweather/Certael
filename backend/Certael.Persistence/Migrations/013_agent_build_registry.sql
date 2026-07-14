CREATE TABLE IF NOT EXISTS certael_agent_builds(
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    build_id text NOT NULL,
    registered_at timestamptz NOT NULL,
    registered_by text NOT NULL,
    revoked_at timestamptz NULL,
    revoked_by text NULL,
    PRIMARY KEY(tenant_id, game_id, environment_id, build_id),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX IF NOT EXISTS certael_agent_builds_active
    ON certael_agent_builds(tenant_id, game_id, environment_id, build_id)
    WHERE revoked_at IS NULL;

ALTER TABLE certael_agent_builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_agent_builds FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_agent_builds_tenant ON certael_agent_builds;
CREATE POLICY certael_agent_builds_tenant ON certael_agent_builds
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
