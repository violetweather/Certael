ALTER TABLE certael_relationship_edges
    ADD COLUMN IF NOT EXISTS authoritative_action_id uuid NULL,
    ADD COLUMN IF NOT EXISTS canonical_payload bytea NULL,
    ADD COLUMN IF NOT EXISTS replay_digest bytea NULL,
    ADD COLUMN IF NOT EXISTS expires_at timestamptz NULL;

CREATE UNIQUE INDEX IF NOT EXISTS certael_relationship_event_identity
    ON certael_relationship_edges (tenant_id, event_id);
CREATE INDEX IF NOT EXISTS certael_relationship_subject_window
    ON certael_relationship_edges
       (tenant_id, game_id, environment_id, source_subject, occurred_at DESC);
CREATE INDEX IF NOT EXISTS certael_relationship_target_window
    ON certael_relationship_edges
       (tenant_id, game_id, environment_id, target_subject, occurred_at DESC);

CREATE TABLE IF NOT EXISTS certael_relationship_profiles (
    tenant_id text NOT NULL,
    profile_id text NOT NULL,
    version text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    stage text NOT NULL CHECK (stage IN ('Shadow','Canary','Enforced','RolledBack')),
    canary_percentage integer NOT NULL CHECK (canary_percentage BETWEEN 0 AND 100),
    canonical_profile bytea NOT NULL,
    signature bytea NOT NULL,
    key_id text NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, profile_id, version)
);

CREATE TABLE IF NOT EXISTS certael_relationship_profile_activity (
    tenant_id text NOT NULL,
    activity_id uuid NOT NULL,
    profile_id text NOT NULL,
    version text NOT NULL,
    activity text NOT NULL,
    actor_subject text NOT NULL,
    details jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, activity_id),
    FOREIGN KEY (tenant_id, profile_id, version)
        REFERENCES certael_relationship_profiles(tenant_id, profile_id, version)
);

CREATE TABLE IF NOT EXISTS certael_relationship_findings (
    tenant_id text NOT NULL,
    finding_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    profile_id text NOT NULL,
    profile_version text NOT NULL,
    profile_stage text NOT NULL,
    rule_id text NOT NULL,
    rule_version text NOT NULL,
    window_days integer NOT NULL CHECK (window_days IN (7,30,90)),
    event_ids uuid[] NOT NULL,
    baseline_version text NOT NULL,
    threshold text NOT NULL,
    replay_digest bytea NOT NULL CHECK (octet_length(replay_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, finding_id)
);
CREATE INDEX IF NOT EXISTS certael_relationship_findings_queue
    ON certael_relationship_findings
       (tenant_id, game_id, environment_id, rule_id, created_at DESC);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'certael_relationship_profiles', 'certael_relationship_profile_activity',
        'certael_relationship_findings']
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
