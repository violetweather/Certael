CREATE TABLE IF NOT EXISTS certael_signed_configurations(
    tenant_id text NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 128
      AND tenant_id ~ '^[A-Za-z0-9._-]+$'),
    artifact_kind integer NOT NULL CHECK (artifact_kind BETWEEN 1 AND 2),
    artifact_id text NOT NULL CHECK (char_length(artifact_id) BETWEEN 1 AND 128
      AND artifact_id ~ '^[A-Za-z0-9._-]+$'),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64
      AND version ~ '^[0-9]+(\.[0-9]+){1,3}$'),
    game_id text NOT NULL CHECK (char_length(game_id) BETWEEN 1 AND 128
      AND game_id ~ '^[A-Za-z0-9._-]+$'),
    environment_id text NOT NULL CHECK (char_length(environment_id) BETWEEN 1 AND 128
      AND environment_id ~ '^[A-Za-z0-9._-]+$'),
    canonical_document bytea NOT NULL CHECK (octet_length(canonical_document) BETWEEN 1 AND 1048576),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 64 AND 512),
    signing_key_id text NOT NULL CHECK (char_length(signing_key_id) BETWEEN 1 AND 128
      AND signing_key_id ~ '^[A-Za-z0-9._-]+$'),
    stage integer NOT NULL CHECK (stage BETWEEN 0 AND 4),
    canary_percentage integer NOT NULL DEFAULT 0 CHECK (canary_percentage BETWEEN 0 AND 99),
    created_at timestamptz NOT NULL,
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    PRIMARY KEY(tenant_id, artifact_kind, artifact_id, version),
    UNIQUE(tenant_id, artifact_kind, digest),
    CHECK ((stage = 2 AND canary_percentage BETWEEN 1 AND 99)
        OR (stage <> 2 AND canary_percentage = 0))
);

CREATE TABLE IF NOT EXISTS certael_signed_configuration_approvals(
    tenant_id text NOT NULL,
    artifact_kind integer NOT NULL,
    artifact_id text NOT NULL,
    version text NOT NULL,
    approver_subject text NOT NULL CHECK (char_length(approver_subject) BETWEEN 1 AND 128),
    approved_at timestamptz NOT NULL,
    artifact_digest bytea NOT NULL CHECK (octet_length(artifact_digest) = 32),
    PRIMARY KEY(tenant_id, artifact_kind, artifact_id, version, approver_subject),
    FOREIGN KEY(tenant_id, artifact_kind, artifact_id, version)
      REFERENCES certael_signed_configurations(tenant_id, artifact_kind, artifact_id, version)
      ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certael_signed_configuration_active(
    tenant_id text NOT NULL,
    artifact_kind integer NOT NULL CHECK (artifact_kind BETWEEN 1 AND 2),
    game_id text NOT NULL,
    environment_id text NOT NULL,
    active_artifact_id text NOT NULL,
    active_version text NOT NULL,
    previous_artifact_id text,
    previous_version text,
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL,
    PRIMARY KEY(tenant_id, artifact_kind, game_id, environment_id),
    FOREIGN KEY(tenant_id, artifact_kind, active_artifact_id, active_version)
      REFERENCES certael_signed_configurations(tenant_id, artifact_kind, artifact_id, version)
);

ALTER TABLE certael_signed_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_signed_configurations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_signed_configurations_tenant ON certael_signed_configurations;
CREATE POLICY certael_signed_configurations_tenant ON certael_signed_configurations
  USING (tenant_id = current_setting('certael.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

ALTER TABLE certael_signed_configuration_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_signed_configuration_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_signed_configuration_approvals_tenant ON certael_signed_configuration_approvals;
CREATE POLICY certael_signed_configuration_approvals_tenant ON certael_signed_configuration_approvals
  USING (tenant_id = current_setting('certael.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));

ALTER TABLE certael_signed_configuration_active ENABLE ROW LEVEL SECURITY;
ALTER TABLE certael_signed_configuration_active FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certael_signed_configuration_active_tenant ON certael_signed_configuration_active;
CREATE POLICY certael_signed_configuration_active_tenant ON certael_signed_configuration_active
  USING (tenant_id = current_setting('certael.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('certael.tenant_id', true));
