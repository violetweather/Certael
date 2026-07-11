ALTER TABLE certael_action_results ALTER COLUMN result DROP NOT NULL;
ALTER TABLE certael_action_results ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'completed';
ALTER TABLE certael_action_results DROP CONSTRAINT IF EXISTS certael_action_results_status_check;
ALTER TABLE certael_action_results ADD CONSTRAINT certael_action_results_status_check
    CHECK (status IN ('processing', 'completed'));
