CREATE TABLE IF NOT EXISTS certael_verdicts (
    tenant_id text NOT NULL,
    verdict_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    session_id text NOT NULL,
    player_subject text NOT NULL,
    risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    recommendation text NOT NULL,
    rule_versions text[] NOT NULL,
    replay_digest bytea NOT NULL CHECK (octet_length(replay_digest) = 32),
    bundle jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, verdict_id)
);
CREATE INDEX IF NOT EXISTS certael_verdicts_search
    ON certael_verdicts (tenant_id, environment_id, player_subject, created_at DESC);

CREATE TABLE IF NOT EXISTS certael_findings (
    tenant_id text NOT NULL,
    finding_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    session_id text NOT NULL,
    player_subject text NOT NULL,
    rule_id text NOT NULL,
    rule_version text NOT NULL,
    rule_pack_digest bytea NOT NULL CHECK (octet_length(rule_pack_digest) = 32),
    action_id uuid NULL,
    signal_family text NOT NULL,
    trust text NOT NULL,
    risk_contribution integer NOT NULL,
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    fields jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, finding_id)
);
CREATE INDEX IF NOT EXISTS certael_findings_search
    ON certael_findings (tenant_id, environment_id, player_subject, observed_at DESC);
CREATE INDEX IF NOT EXISTS certael_findings_rule
    ON certael_findings (tenant_id, game_id, environment_id, rule_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS certael_verdict_findings (
    tenant_id text NOT NULL,
    verdict_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, verdict_id, finding_id),
    FOREIGN KEY (tenant_id, verdict_id) REFERENCES certael_verdicts(tenant_id, verdict_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, finding_id) REFERENCES certael_findings(tenant_id, finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certael_cases (
    tenant_id text NOT NULL,
    case_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    player_subject text NOT NULL,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
    summary text NOT NULL CHECK (length(summary) BETWEEN 1 AND 4096),
    state text NOT NULL CHECK (state IN ('Open', 'InReview', 'Resolved', 'Dismissed')),
    signed_policy_id text NOT NULL,
    signed_policy_version text NOT NULL,
    deduplication_key bytea NOT NULL CHECK (octet_length(deduplication_key) = 32),
    deduplication_until timestamptz NOT NULL,
    assigned_to text NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, case_id)
);
CREATE INDEX IF NOT EXISTS certael_cases_queue
    ON certael_cases (tenant_id, environment_id, state, updated_at DESC);
CREATE INDEX IF NOT EXISTS certael_cases_player
    ON certael_cases (tenant_id, environment_id, player_subject, updated_at DESC);
CREATE INDEX IF NOT EXISTS certael_cases_deduplicate
    ON certael_cases (tenant_id, deduplication_key, deduplication_until DESC);

CREATE TABLE IF NOT EXISTS certael_case_evidence (
    tenant_id text NOT NULL,
    case_evidence_id uuid NOT NULL,
    case_id uuid NOT NULL,
    verdict_id uuid NOT NULL,
    finding_id uuid NULL,
    attached_by text NOT NULL,
    attached_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, case_evidence_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES certael_cases(tenant_id, case_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, verdict_id) REFERENCES certael_verdicts(tenant_id, verdict_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, finding_id) REFERENCES certael_findings(tenant_id, finding_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS certael_case_evidence_unique
    ON certael_case_evidence (tenant_id, case_id, verdict_id, finding_id)
    NULLS NOT DISTINCT;

CREATE TABLE IF NOT EXISTS certael_case_notes (
    tenant_id text NOT NULL,
    note_id uuid NOT NULL,
    case_id uuid NOT NULL,
    author_subject text NOT NULL,
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 4096),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, note_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES certael_cases(tenant_id, case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS certael_case_notes_case
    ON certael_case_notes (tenant_id, case_id, created_at);

CREATE TABLE IF NOT EXISTS certael_case_assignments (
    tenant_id text NOT NULL,
    assignment_id uuid NOT NULL,
    case_id uuid NOT NULL,
    assigned_to text NULL,
    assigned_by text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, assignment_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES certael_cases(tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certael_case_dispositions (
    tenant_id text NOT NULL,
    disposition_id uuid NOT NULL,
    case_id uuid NOT NULL,
    disposition text NOT NULL CHECK (disposition IN (
        'ConfirmedAbuse', 'FalsePositive', 'ExpectedBehavior', 'InsufficientEvidence', 'Duplicate')),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, disposition_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES certael_cases(tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certael_bounded_actions (
    tenant_id text NOT NULL,
    bounded_action_id uuid NOT NULL,
    case_id uuid NOT NULL,
    action_kind text NOT NULL CHECK (action_kind IN (
        'RevokeSession', 'RejectAction', 'IncreaseSampling', 'TemporaryRestriction', 'RecommendKick')),
    target_type text NOT NULL,
    target_id text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
    requested_by text NOT NULL,
    approved_by text NOT NULL,
    authorization_digest bytea NOT NULL CHECK (octet_length(authorization_digest) = 32),
    status text NOT NULL CHECK (status IN ('Approved', 'Executing', 'Succeeded', 'Failed', 'Expired')),
    public_result text NULL,
    requested_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    PRIMARY KEY (tenant_id, bounded_action_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES certael_cases(tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certael_case_activity (
    tenant_id text NOT NULL,
    activity_id uuid NOT NULL,
    case_id uuid NOT NULL,
    actor_subject text NOT NULL,
    activity_type text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
    details jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, activity_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES certael_cases(tenant_id, case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS certael_case_activity_case
    ON certael_case_activity (tenant_id, case_id, occurred_at, activity_id);

CREATE OR REPLACE FUNCTION certael_reject_append_only_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'append-only record cannot be changed' USING ERRCODE = '55000';
END
$$;

DROP TRIGGER IF EXISTS certael_case_activity_append_only ON certael_case_activity;
CREATE TRIGGER certael_case_activity_append_only
    BEFORE UPDATE OR DELETE ON certael_case_activity
    FOR EACH ROW EXECUTE FUNCTION certael_reject_append_only_mutation();
DROP TRIGGER IF EXISTS certael_case_notes_append_only ON certael_case_notes;
CREATE TRIGGER certael_case_notes_append_only
    BEFORE UPDATE OR DELETE ON certael_case_notes
    FOR EACH ROW EXECUTE FUNCTION certael_reject_append_only_mutation();
DROP TRIGGER IF EXISTS certael_case_assignments_append_only ON certael_case_assignments;
CREATE TRIGGER certael_case_assignments_append_only
    BEFORE UPDATE OR DELETE ON certael_case_assignments
    FOR EACH ROW EXECUTE FUNCTION certael_reject_append_only_mutation();
DROP TRIGGER IF EXISTS certael_case_dispositions_append_only ON certael_case_dispositions;
CREATE TRIGGER certael_case_dispositions_append_only
    BEFORE UPDATE OR DELETE ON certael_case_dispositions
    FOR EACH ROW EXECUTE FUNCTION certael_reject_append_only_mutation();
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'certael_verdicts', 'certael_findings', 'certael_verdict_findings',
        'certael_cases', 'certael_case_evidence', 'certael_case_notes',
        'certael_case_assignments', 'certael_case_dispositions',
        'certael_bounded_actions', 'certael_case_activity']
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
