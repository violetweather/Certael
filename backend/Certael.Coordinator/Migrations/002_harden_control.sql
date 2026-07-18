ALTER TABLE certael_region_transfer_grants
 ADD COLUMN IF NOT EXISTS canonical_digest bytea,
 ADD COLUMN IF NOT EXISTS issued_at timestamptz,
 ADD COLUMN IF NOT EXISTS destination_server text,
 ADD COLUMN IF NOT EXISTS destination_fencing_epoch bigint;
UPDATE certael_region_transfer_grants
 SET canonical_digest=nonce_digest WHERE canonical_digest IS NULL;
UPDATE certael_region_transfer_grants
 SET issued_at=created_at WHERE issued_at IS NULL;
ALTER TABLE certael_region_transfer_grants
 ALTER COLUMN canonical_digest SET NOT NULL,
 ALTER COLUMN issued_at SET NOT NULL;
ALTER TABLE certael_coordinator_audit
 ADD COLUMN IF NOT EXISTS game_id text NOT NULL DEFAULT 'legacy',
 ADD COLUMN IF NOT EXISTS environment_id text NOT NULL DEFAULT 'legacy';
