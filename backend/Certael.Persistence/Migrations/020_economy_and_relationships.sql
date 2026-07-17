CREATE TABLE IF NOT EXISTS certael_economy_events (
    tenant_id text NOT NULL,
    event_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    player_subject text NOT NULL,
    event_kind text NOT NULL CHECK (event_kind IN ('LedgerTransaction', 'ItemLineageMutation')),
    authoritative_action_id uuid NOT NULL,
    transaction_id text NULL,
    mutation_id text NULL,
    reason_code text NOT NULL,
    canonical_payload bytea NOT NULL,
    replay_digest bytea NOT NULL CHECK (octet_length(replay_digest) = 32),
    occurred_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS certael_economy_transaction_lookup
    ON certael_economy_events (tenant_id, game_id, environment_id, transaction_id)
    WHERE transaction_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS certael_economy_player_timeline
    ON certael_economy_events (tenant_id, environment_id, player_subject, occurred_at DESC);

CREATE TABLE IF NOT EXISTS certael_economy_ledger_lines (
    tenant_id text NOT NULL,
    event_id uuid NOT NULL,
    line_number integer NOT NULL,
    account_id text NOT NULL,
    asset_id text NOT NULL,
    quantity bigint NOT NULL,
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, event_id, line_number),
    FOREIGN KEY (tenant_id, event_id) REFERENCES certael_economy_events(tenant_id, event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS certael_economy_ledger_account
    ON certael_economy_ledger_lines (tenant_id, account_id, asset_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS certael_item_lineage (
    tenant_id text NOT NULL,
    event_id uuid NOT NULL,
    item_id text NOT NULL,
    parent_item_id text NULL,
    asset_id text NOT NULL,
    account_id text NOT NULL,
    mutation_kind text NOT NULL CHECK (mutation_kind IN ('Create', 'Transfer', 'Destroy')),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES certael_economy_events(tenant_id, event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS certael_item_lineage_item
    ON certael_item_lineage (tenant_id, item_id, occurred_at);

CREATE TABLE IF NOT EXISTS certael_economy_profiles (
    tenant_id text NOT NULL,
    profile_id text NOT NULL,
    version text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    stage text NOT NULL CHECK (stage IN ('Shadow', 'Canary', 'Enforced', 'RolledBack')),
    canary_percentage integer NOT NULL CHECK (canary_percentage BETWEEN 0 AND 100),
    canonical_profile bytea NOT NULL,
    signature bytea NOT NULL,
    key_id text NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, profile_id, version)
);

CREATE TABLE IF NOT EXISTS certael_relationship_edges (
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    event_id uuid NOT NULL,
    edge_kind text NOT NULL CHECK (edge_kind IN ('Match','Outcome','Trade','Gift','Marketplace','Reward','Party')),
    source_subject text NOT NULL,
    target_subject text NOT NULL,
    weight bigint NOT NULL,
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, event_id, edge_kind, source_subject, target_subject)
);
CREATE INDEX IF NOT EXISTS certael_relationship_window
    ON certael_relationship_edges (tenant_id, game_id, environment_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS certael_economy_findings (
    tenant_id text NOT NULL,
    finding_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    rule_id text NOT NULL,
    rule_version text NOT NULL,
    event_ids uuid[] NOT NULL,
    authoritative_fields jsonb NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    replay_digest bytea NOT NULL CHECK (octet_length(replay_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, finding_id)
);
CREATE INDEX IF NOT EXISTS certael_economy_findings_rule
    ON certael_economy_findings (tenant_id, game_id, environment_id, rule_id, created_at DESC);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'certael_economy_events', 'certael_economy_ledger_lines', 'certael_item_lineage',
        'certael_economy_profiles', 'certael_relationship_edges', 'certael_economy_findings']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_tenant', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (tenant_id = current_setting(''certael.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''certael.tenant_id'', true))',
            table_name || '_tenant', table_name);
    END LOOP;
END
$$;
