CREATE TABLE IF NOT EXISTS certael_sessions (
    session_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    player_subject text NOT NULL,
    match_id text NOT NULL,
    authoritative_server_id text NOT NULL,
    build_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    minimum_sequence numeric(20,0) NOT NULL,
    maximum_sequence numeric(20,0) NOT NULL,
    ephemeral_public_key bytea NOT NULL CHECK (octet_length(ephemeral_public_key) = 32),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS certael_sessions_tenant_player
    ON certael_sessions (tenant_id, player_subject);

CREATE TABLE IF NOT EXISTS certael_action_results (
    session_id text NOT NULL REFERENCES certael_sessions(session_id) ON DELETE CASCADE,
    action_id uuid NOT NULL,
    response_type text NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, action_id)
);

CREATE TABLE IF NOT EXISTS certael_outbox (
    outbox_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    session_id text NOT NULL,
    action_id uuid NOT NULL,
    event_type text NOT NULL,
    schema_version integer NOT NULL,
    payload bytea NOT NULL,
    occurred_at timestamptz NOT NULL,
    published_at timestamptz NULL,
    attempts integer NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS certael_outbox_action_event
    ON certael_outbox(session_id, action_id, event_type);
CREATE INDEX IF NOT EXISTS certael_outbox_pending
    ON certael_outbox(occurred_at) WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS certael_evidence (
    tenant_id text NOT NULL,
    verdict_id uuid NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    player_subject text NOT NULL,
    bundle jsonb NOT NULL,
    replay_digest bytea NOT NULL CHECK (octet_length(replay_digest) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, verdict_id)
);
CREATE INDEX IF NOT EXISTS certael_evidence_retention ON certael_evidence(expires_at);
CREATE INDEX IF NOT EXISTS certael_evidence_player ON certael_evidence(tenant_id, player_subject);

ALTER TABLE certael_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_evidence_tenant ON certael_evidence;
CREATE POLICY certael_evidence_tenant ON certael_evidence
    USING (tenant_id = current_setting('certael.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
