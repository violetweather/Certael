ALTER TABLE certael_outbox
    ADD COLUMN IF NOT EXISTS delivery_state text NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS lease_owner text NULL,
    ADD COLUMN IF NOT EXISTS leased_until timestamptz NULL,
    ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_error text NULL,
    ADD COLUMN IF NOT EXISTS dead_lettered_at timestamptz NULL;

UPDATE certael_outbox
SET delivery_state = 'published', next_attempt_at = published_at
WHERE published_at IS NOT NULL AND delivery_state <> 'published';

ALTER TABLE certael_outbox
    DROP CONSTRAINT IF EXISTS certael_outbox_delivery_state_check;
ALTER TABLE certael_outbox
    ADD CONSTRAINT certael_outbox_delivery_state_check
    CHECK (delivery_state IN ('pending', 'leased', 'published', 'retry', 'dead_letter'));

DROP INDEX IF EXISTS certael_outbox_pending;
CREATE INDEX IF NOT EXISTS certael_outbox_dispatchable
    ON certael_outbox (tenant_id, next_attempt_at, occurred_at, outbox_id)
    WHERE delivery_state IN ('pending', 'retry', 'leased');
CREATE INDEX IF NOT EXISTS certael_outbox_dead_letters
    ON certael_outbox (tenant_id, dead_lettered_at DESC)
    WHERE delivery_state = 'dead_letter';

CREATE TABLE IF NOT EXISTS certael_tenant_catalog (
    tenant_id text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT true,
    event_processing_enabled boolean NOT NULL DEFAULT true,
    analytics_processing_enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO certael_tenant_catalog (tenant_id)
SELECT DISTINCT tenant_id FROM certael_outbox
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS certael_event_receipts (
    tenant_id text NOT NULL,
    consumer_name text NOT NULL,
    event_id uuid NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, consumer_name, event_id)
);
CREATE INDEX IF NOT EXISTS certael_event_receipts_retention
    ON certael_event_receipts (processed_at);

ALTER TABLE certael_event_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_event_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_event_receipts_tenant ON certael_event_receipts;
CREATE POLICY certael_event_receipts_tenant ON certael_event_receipts
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
