-- Pre-manifest approvals remain as history but cannot authorize protected
-- launch. Registration may upgrade one such row exactly once with a manifest.
ALTER TABLE certael_agent_builds
    ADD COLUMN signed_build_manifest bytea;

ALTER TABLE certael_agent_builds
    ADD CONSTRAINT certael_agent_build_manifest_size
    CHECK (signed_build_manifest IS NULL
        OR octet_length(signed_build_manifest) BETWEEN 1 AND 65536);
