CREATE TABLE IF NOT EXISTS certael_match_leases(
 tenant_id text NOT NULL, game_id text NOT NULL, environment_id text NOT NULL, match_id text NOT NULL,
 owner_region text NOT NULL, owner_server text NOT NULL, fencing_epoch bigint NOT NULL CHECK(fencing_epoch > 0),
 expires_at timestamptz NOT NULL, released_at timestamptz NULL, PRIMARY KEY(tenant_id,game_id,environment_id,match_id));
CREATE TABLE IF NOT EXISTS certael_region_transfer_grants(
 grant_id uuid PRIMARY KEY, tenant_id text NOT NULL, game_id text NOT NULL, environment_id text NOT NULL,
 match_id text NOT NULL, player_subject text NOT NULL, source_region text NOT NULL, destination_region text NOT NULL,
 fencing_epoch bigint NOT NULL, nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32), expires_at timestamptz NOT NULL,
 redeemed_at timestamptz NULL, redeemed_by text NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS certael_coordinator_audit(
 audit_id uuid PRIMARY KEY, tenant_id text NOT NULL, match_id text NOT NULL, action text NOT NULL,
 actor text NOT NULL, fencing_epoch bigint NOT NULL, details jsonb NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now());
