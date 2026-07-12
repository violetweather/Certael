CREATE TABLE IF NOT EXISTS certael_audit (
    audit_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    operator_subject text NOT NULL,
    operation text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    reason text NOT NULL,
    before_digest text NULL,
    after_digest text NULL,
    request_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    succeeded boolean NOT NULL,
    source_network text NULL,
    workload_identity text NULL
);
ALTER TABLE certael_audit ADD COLUMN IF NOT EXISTS source_network text NULL;
ALTER TABLE certael_audit ADD COLUMN IF NOT EXISTS workload_identity text NULL;
CREATE INDEX IF NOT EXISTS certael_audit_recent ON certael_audit(tenant_id,environment_id,occurred_at DESC);
ALTER TABLE certael_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_audit_tenant ON certael_audit;
CREATE POLICY certael_audit_tenant ON certael_audit
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
