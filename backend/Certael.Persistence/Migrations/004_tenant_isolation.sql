ALTER TABLE certael_action_results ADD COLUMN IF NOT EXISTS tenant_id text;
UPDATE certael_action_results results
SET tenant_id = sessions.tenant_id
FROM certael_sessions sessions
WHERE results.session_id = sessions.session_id AND results.tenant_id IS NULL;
ALTER TABLE certael_action_results ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS certael_action_results_tenant ON certael_action_results(tenant_id, session_id);

ALTER TABLE certael_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_sessions_tenant ON certael_sessions;
CREATE POLICY certael_sessions_tenant ON certael_sessions
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

ALTER TABLE certael_action_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_action_results FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_action_results_tenant ON certael_action_results;
CREATE POLICY certael_action_results_tenant ON certael_action_results
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

ALTER TABLE certael_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_outbox_tenant ON certael_outbox;
CREATE POLICY certael_outbox_tenant ON certael_outbox
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
