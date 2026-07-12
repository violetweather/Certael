ALTER TABLE certael_audit ADD COLUMN IF NOT EXISTS source_network text NULL;
ALTER TABLE certael_audit ADD COLUMN IF NOT EXISTS workload_identity text NULL;
