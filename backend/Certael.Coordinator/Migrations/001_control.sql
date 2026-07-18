CREATE TABLE IF NOT EXISTS certael_match_leases(
 tenant_id text NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128),
 game_id text NOT NULL CHECK(length(game_id) BETWEEN 1 AND 128),
 environment_id text NOT NULL CHECK(length(environment_id) BETWEEN 1 AND 128),
 match_id text NOT NULL CHECK(length(match_id) BETWEEN 1 AND 128),
 owner_region text NOT NULL CHECK(length(owner_region) BETWEEN 1 AND 128),
 owner_server text NOT NULL CHECK(length(owner_server) BETWEEN 1 AND 128),
 fencing_epoch bigint NOT NULL CHECK(fencing_epoch > 0),
 expires_at timestamptz NOT NULL,
 released_at timestamptz NULL,
 PRIMARY KEY(tenant_id,game_id,environment_id,match_id));

CREATE TABLE IF NOT EXISTS certael_region_transfer_grants(
 grant_id uuid PRIMARY KEY,
 tenant_id text NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128),
 game_id text NOT NULL CHECK(length(game_id) BETWEEN 1 AND 128),
 environment_id text NOT NULL CHECK(length(environment_id) BETWEEN 1 AND 128),
 match_id text NOT NULL CHECK(length(match_id) BETWEEN 1 AND 128),
 player_subject text NOT NULL CHECK(length(player_subject) BETWEEN 1 AND 128),
 source_region text NOT NULL CHECK(length(source_region) BETWEEN 1 AND 128),
 destination_region text NOT NULL CHECK(length(destination_region) BETWEEN 1 AND 128),
 fencing_epoch bigint NOT NULL CHECK(fencing_epoch > 0),
 nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32),
 canonical_digest bytea NOT NULL CHECK(octet_length(canonical_digest)=32),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at > issued_at),
 redeemed_at timestamptz NULL,
 redeemed_by text NULL,
 destination_server text NULL,
 destination_fencing_epoch bigint NULL CHECK(destination_fencing_epoch > 0),
 created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ix_region_transfer_scope
 ON certael_region_transfer_grants(tenant_id,game_id,environment_id,match_id,expires_at);

CREATE TABLE IF NOT EXISTS certael_coordinator_audit(
 audit_id uuid PRIMARY KEY,
 tenant_id text NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128),
 game_id text NOT NULL CHECK(length(game_id) BETWEEN 1 AND 128),
 environment_id text NOT NULL CHECK(length(environment_id) BETWEEN 1 AND 128),
 match_id text NOT NULL CHECK(length(match_id) BETWEEN 1 AND 128),
 action text NOT NULL CHECK(length(action) BETWEEN 1 AND 128),
 actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
 fencing_epoch bigint NOT NULL CHECK(fencing_epoch > 0),
 details jsonb NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ix_coordinator_audit_scope
 ON certael_coordinator_audit(tenant_id,game_id,environment_id,match_id,occurred_at DESC);
