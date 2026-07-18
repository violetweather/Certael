CREATE TABLE IF NOT EXISTS certael_economy_profile_activity (
  tenant_id text NOT NULL,
  activity_id uuid NOT NULL,
  profile_id text NOT NULL,
  version text NOT NULL,
  activity text NOT NULL CHECK (activity IN ('ProfileAdded','ProfilePromoted','ProfileRolledBack','ProfileSuperseded')),
  actor_subject text NOT NULL,
  details jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,activity_id),
  FOREIGN KEY (tenant_id,profile_id,version)
    REFERENCES certael_economy_profiles(tenant_id,profile_id,version) ON DELETE CASCADE
);

ALTER TABLE certael_economy_profile_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_economy_profile_activity FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_economy_profile_activity_tenant
  ON certael_economy_profile_activity;
CREATE POLICY certael_economy_profile_activity_tenant
  ON certael_economy_profile_activity
  USING (tenant_id=current_setting('certael.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('certael.tenant_id',true));

CREATE INDEX IF NOT EXISTS certael_economy_profile_activity_timeline
  ON certael_economy_profile_activity(tenant_id,profile_id,version,occurred_at);
