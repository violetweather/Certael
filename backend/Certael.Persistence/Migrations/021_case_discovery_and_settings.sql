ALTER TABLE certael_cases
    ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'General',
    ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE certael_cases
    DROP CONSTRAINT IF EXISTS certael_cases_category_length;
ALTER TABLE certael_cases
    ADD CONSTRAINT certael_cases_category_length CHECK (length(category) BETWEEN 1 AND 96);
ALTER TABLE certael_cases
    DROP CONSTRAINT IF EXISTS certael_cases_metadata_array;
ALTER TABLE certael_cases
    ADD CONSTRAINT certael_cases_metadata_array CHECK (jsonb_typeof(metadata) = 'array');

CREATE INDEX IF NOT EXISTS certael_cases_category
    ON certael_cases (tenant_id, environment_id, category, updated_at DESC, case_id);
CREATE INDEX IF NOT EXISTS certael_cases_metadata
    ON certael_cases USING gin (metadata jsonb_path_ops);
CREATE INDEX IF NOT EXISTS certael_findings_signal
    ON certael_findings (tenant_id, game_id, environment_id, signal_family, observed_at DESC);

CREATE TABLE IF NOT EXISTS certael_case_categories (
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    category_key text NOT NULL CHECK (length(category_key) BETWEEN 1 AND 96),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    description text NOT NULL CHECK (length(description) <= 1024),
    enabled boolean NOT NULL DEFAULT true,
    sort_order integer NOT NULL DEFAULT 0,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, game_id, environment_id, category_key)
);

CREATE TABLE IF NOT EXISTS certael_case_metadata_definitions (
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    metadata_key text NOT NULL CHECK (length(metadata_key) BETWEEN 1 AND 96),
    label text NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    value_type text NOT NULL CHECK (value_type IN (
        'Text', 'Number', 'Boolean', 'DateTime', 'Enumeration', 'Identifier')),
    enumeration_values jsonb NOT NULL DEFAULT '[]'::jsonb,
    sensitive boolean NOT NULL DEFAULT false,
    searchable boolean NOT NULL DEFAULT false,
    required boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, game_id, environment_id, metadata_key),
    CHECK (jsonb_typeof(enumeration_values) = 'array'),
    CHECK (NOT sensitive OR NOT searchable)
);

ALTER TABLE certael_case_categories
    ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE certael_case_metadata_definitions
    ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE certael_case_categories
    DROP CONSTRAINT IF EXISTS certael_case_categories_version_positive;
ALTER TABLE certael_case_categories
    ADD CONSTRAINT certael_case_categories_version_positive CHECK (version > 0);
ALTER TABLE certael_case_metadata_definitions
    DROP CONSTRAINT IF EXISTS certael_case_metadata_definitions_version_positive;
ALTER TABLE certael_case_metadata_definitions
    ADD CONSTRAINT certael_case_metadata_definitions_version_positive CHECK (version > 0);

CREATE TABLE IF NOT EXISTS certael_case_settings_activity (
    activity_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    game_id text NOT NULL,
    environment_id text NOT NULL,
    setting_kind text NOT NULL CHECK (setting_kind IN ('Category', 'Metadata')),
    setting_key text NOT NULL CHECK (length(setting_key) BETWEEN 1 AND 96),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    version bigint NOT NULL CHECK (version > 0),
    details jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX IF NOT EXISTS certael_case_settings_activity_scope
    ON certael_case_settings_activity
    (tenant_id, game_id, environment_id, occurred_at DESC, activity_id);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'certael_case_categories', 'certael_case_metadata_definitions',
        'certael_case_settings_activity']
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
