ALTER TABLE certael_agent_sessions
    ADD CONSTRAINT certael_agent_sessions_identifiers CHECK (
        tenant_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND game_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND environment_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND player_subject ~ '^[A-Za-z0-9._-]{1,128}$'
        AND match_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND build_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND authoritative_server_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND agent_session_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND (revocation_reason IS NULL OR char_length(revocation_reason) BETWEEN 1 AND 512));

ALTER TABLE certael_agent_policies
    ADD CONSTRAINT certael_agent_policies_identifiers CHECK (
        tenant_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND policy_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND game_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND environment_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND minimum_agent_version ~ '^[A-Za-z0-9.+_-]{1,64}$'
        AND signing_key_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND char_length(created_by) BETWEEN 1 AND 128
        AND char_length(updated_by) BETWEEN 1 AND 128);

ALTER TABLE certael_agent_policy_approvals
    ADD CONSTRAINT certael_agent_policy_approvals_identifiers CHECK (
        tenant_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND policy_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND char_length(approver_subject) BETWEEN 1 AND 128);

ALTER TABLE certael_ticket_redemptions
    ADD CONSTRAINT certael_ticket_redemptions_identifiers CHECK (
        tenant_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND environment_id ~ '^[A-Za-z0-9._-]{1,128}$');

ALTER TABLE certael_agent_builds
    ADD CONSTRAINT certael_agent_builds_identifiers CHECK (
        tenant_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND game_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND environment_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND build_id ~ '^[A-Za-z0-9._-]{1,128}$'
        AND char_length(registered_by) BETWEEN 1 AND 128
        AND (revoked_by IS NULL OR char_length(revoked_by) BETWEEN 1 AND 128));
