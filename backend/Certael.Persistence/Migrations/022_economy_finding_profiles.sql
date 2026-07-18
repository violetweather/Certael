ALTER TABLE certael_economy_findings
  ADD COLUMN IF NOT EXISTS profile_id text NOT NULL DEFAULT 'legacy',
  ADD COLUMN IF NOT EXISTS profile_version text NOT NULL DEFAULT '0',
  ADD COLUMN IF NOT EXISTS profile_stage text NOT NULL DEFAULT 'Shadow';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'certael_economy_findings_profile_stage_check'
  ) THEN
    ALTER TABLE certael_economy_findings ADD CONSTRAINT certael_economy_findings_profile_stage_check
      CHECK (profile_stage IN ('Shadow','Canary','Enforced','RolledBack'));
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS certael_economy_findings_profile
  ON certael_economy_findings
    (tenant_id, game_id, environment_id, profile_id, profile_version, created_at DESC);
