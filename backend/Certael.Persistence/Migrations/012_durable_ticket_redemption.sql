CREATE TABLE IF NOT EXISTS certael_ticket_redemptions(
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    ticket_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    redeemed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id, environment_id, ticket_id)
);

CREATE INDEX IF NOT EXISTS certael_ticket_redemptions_expiry
    ON certael_ticket_redemptions(tenant_id, environment_id, expires_at);

ALTER TABLE certael_ticket_redemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_ticket_redemptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_ticket_redemptions_tenant ON certael_ticket_redemptions;
CREATE POLICY certael_ticket_redemptions_tenant ON certael_ticket_redemptions
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
