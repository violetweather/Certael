using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Certael.Server.Agent;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresAgentPolicyStore(
    NpgsqlDataSource dataSource,
    AgentGrantSigner signer,
    TimeProvider timeProvider) : IAgentPolicyResolver, IAgentPolicyAdministration
{
    public async ValueTask<AgentPolicyDeployment> AddDraftAsync(AgentPolicyClaims claims,
        string author, CancellationToken cancellationToken)
    {
        string subject = Subject(author);
        DateTimeOffset now = timeProvider.GetUtcNow();
        SignedAgentPolicy signed = signer.IssuePolicy(claims, now);
        byte[] digest = AgentGrantCodec.PolicyDigest(signed);
        const string sql = """
            INSERT INTO certael_agent_policies(tenant_id, policy_id, protocol_version,
              game_id, environment_id, requirement_mode, heartbeat_seconds, report_seconds,
              disconnect_grace_seconds, minimum_agent_version, expires_at, signed_claims,
              signature, signing_key_id, policy_digest, stage, canary_percentage, created_at,
              created_by, updated_at, updated_by)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,0,$17,$18,$17,$18)
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, claims.TenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        object[] values = [claims.TenantId, claims.PolicyId, checked((int)claims.ProtocolVersion),
            claims.GameId, claims.EnvironmentId, (int)claims.RequirementMode,
            checked((int)claims.HeartbeatSeconds), checked((int)claims.ReportSeconds),
            checked((int)claims.DisconnectGraceSeconds), claims.MinimumAgentVersion,
            claims.ExpiresAt, signed.Claims, signed.Signature, signed.KeyId, digest,
            (int)AgentPolicyDeploymentStage.Draft, now, subject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        try { await command.ExecuteNonQueryAsync(cancellationToken); }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        { throw new AgentPolicyLifecycleException("Policy ID is immutable and already exists."); }
        await transaction.CommitAsync(cancellationToken);
        return new(claims, signed, digest, AgentPolicyDeploymentStage.Draft, 0, [], now, subject);
    }

    public async ValueTask<AgentPolicyDeployment> ApproveAsync(string tenantId, string policyId,
        string approver, CancellationToken cancellationToken)
    {
        string subject = Subject(approver);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        AgentPolicyDeployment current = await Read(connection, transaction, tenantId, policyId,
            true, cancellationToken);
        if (current.Stage == AgentPolicyDeploymentStage.Retired)
            throw new AgentPolicyLifecycleException("A retired policy cannot be approved.");
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO certael_agent_policy_approvals(tenant_id, policy_id, approver_subject,
              approved_at, policy_digest) VALUES($1,$2,$3,$4,$5)
            ON CONFLICT(tenant_id, policy_id, approver_subject) DO NOTHING
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue(tenantId); insert.Parameters.AddWithValue(policyId);
            insert.Parameters.AddWithValue(subject); insert.Parameters.AddWithValue(now);
            insert.Parameters.AddWithValue(current.PolicyDigest);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await Touch(connection, transaction, tenantId, policyId, now, subject, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, policyId, cancellationToken);
    }

    public async ValueTask<AgentPolicyDeployment> PromoteAsync(string tenantId, string policyId,
        AgentPolicyDeploymentStage stage, int canaryPercentage, string operatorSubject,
        CancellationToken cancellationToken)
    {
        ValidateStage(stage, canaryPercentage);
        string subject = Subject(operatorSubject);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        AgentPolicyDeployment current = await Read(connection, transaction, tenantId, policyId,
            true, cancellationToken);
        if (current.Stage == AgentPolicyDeploymentStage.Retired)
            throw new AgentPolicyLifecycleException("A retired policy cannot be promoted.");
        if (stage == AgentPolicyDeploymentStage.Shadow
            && current.Claims.RequirementMode == AgentRequirementMode.Required)
            throw new AgentPolicyLifecycleException(
                "A shadow policy cannot require Agent enforcement.");
        int required = stage == AgentPolicyDeploymentStage.Enforced ? 2 : 1;
        if (current.Approvals.Select(value => value.ApproverSubject)
            .Distinct(StringComparer.Ordinal).Count() < required)
            throw new AgentPolicyLifecycleException($"{stage} requires {required} distinct approvals.");
        if (current.Approvals.Any(value => !CryptographicOperations.FixedTimeEquals(
            value.PolicyDigest, current.PolicyDigest)))
            throw new AgentPolicyLifecycleException("Approval does not match the signed policy.");
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using var update = new NpgsqlCommand("""
            UPDATE certael_agent_policies SET stage=$3, canary_percentage=$4,
              updated_at=$5, updated_by=$6 WHERE tenant_id=$1 AND policy_id=$2
            """, connection, transaction);
        object[] values = [tenantId, policyId, (int)stage, canaryPercentage, now, subject];
        foreach (object value in values) update.Parameters.AddWithValue(value);
        await update.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, policyId, cancellationToken);
    }

    public async ValueTask<AgentPolicyDeployment> RetireAsync(string tenantId, string policyId,
        string operatorSubject, CancellationToken cancellationToken)
    {
        string subject = Subject(operatorSubject);
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await Read(connection, transaction, tenantId, policyId, true, cancellationToken);
        await using var update = new NpgsqlCommand("""
            UPDATE certael_agent_policies SET stage=$3, canary_percentage=0,
              updated_at=$4, updated_by=$5 WHERE tenant_id=$1 AND policy_id=$2
            """, connection, transaction);
        object[] values = [tenantId, policyId, (int)AgentPolicyDeploymentStage.Retired, now, subject];
        foreach (object value in values) update.Parameters.AddWithValue(value);
        await update.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, policyId, cancellationToken);
    }

    public async ValueTask<AgentPolicyDeployment> ResolveAsync(string policyId, string tenantId,
        string gameId, string environmentId, string assignmentKey, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        AgentPolicyDeployment deployment = await GetAsync(tenantId, policyId, cancellationToken);
        if (!string.Equals(deployment.Claims.GameId, gameId, StringComparison.Ordinal)
            || !string.Equals(deployment.Claims.EnvironmentId, environmentId, StringComparison.Ordinal)
            || deployment.Claims.ExpiresAt <= now)
            throw new AgentPolicyLifecycleException("Policy binding is invalid or expired.");
        bool applies = deployment.Stage is AgentPolicyDeploymentStage.Shadow
                or AgentPolicyDeploymentStage.Enforced
            || deployment.Stage == AgentPolicyDeploymentStage.Canary
                && CanaryBucket(assignmentKey) < deployment.CanaryPercentage;
        return applies ? deployment
            : throw new AgentPolicyLifecycleException("Policy is not approved for this session.");
    }

    public async ValueTask<AgentPolicyDeployment> GetAsync(string tenantId, string policyId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        AgentPolicyDeployment result = await Read(connection, transaction, tenantId, policyId,
            false, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static async Task<AgentPolicyDeployment> Read(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, string policyId, bool forUpdate,
        CancellationToken cancellationToken)
    {
        string sql = """
            SELECT protocol_version, game_id, environment_id, requirement_mode,
              heartbeat_seconds, report_seconds, disconnect_grace_seconds,
              minimum_agent_version, expires_at, signed_claims, signature, signing_key_id,
              policy_digest, stage, canary_percentage, updated_at, updated_by
            FROM certael_agent_policies WHERE tenant_id=$1 AND policy_id=$2
            """ + (forUpdate ? " FOR UPDATE" : string.Empty);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(policyId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            throw new AgentPolicyLifecycleException("Policy does not exist.");
        var claims = new AgentPolicyClaims(checked((uint)reader.GetInt32(0)), policyId, tenantId,
            reader.GetString(1), reader.GetString(2),
            (AgentRequirementMode)reader.GetInt32(3), checked((uint)reader.GetInt32(4)),
            checked((uint)reader.GetInt32(5)), checked((uint)reader.GetInt32(6)),
            reader.GetString(7), reader.GetFieldValue<DateTimeOffset>(8));
        var signed = new SignedAgentPolicy(reader.GetFieldValue<byte[]>(9),
            reader.GetFieldValue<byte[]>(10), reader.GetString(11));
        byte[] digest = reader.GetFieldValue<byte[]>(12);
        var stage = (AgentPolicyDeploymentStage)reader.GetInt32(13);
        int canary = reader.GetInt32(14);
        DateTimeOffset updatedAt = reader.GetFieldValue<DateTimeOffset>(15);
        string updatedBy = reader.GetString(16);
        await reader.DisposeAsync();
        var approvals = new List<AgentPolicyApproval>();
        await using var approvalCommand = new NpgsqlCommand("""
            SELECT approver_subject, approved_at, policy_digest
            FROM certael_agent_policy_approvals WHERE tenant_id=$1 AND policy_id=$2
            ORDER BY approver_subject
            """, connection, transaction);
        approvalCommand.Parameters.AddWithValue(tenantId); approvalCommand.Parameters.AddWithValue(policyId);
        await using NpgsqlDataReader approvalsReader =
            await approvalCommand.ExecuteReaderAsync(cancellationToken);
        while (await approvalsReader.ReadAsync(cancellationToken))
            approvals.Add(new(approvalsReader.GetString(0),
                approvalsReader.GetFieldValue<DateTimeOffset>(1),
                approvalsReader.GetFieldValue<byte[]>(2)));
        if (!CryptographicOperations.FixedTimeEquals(digest, AgentGrantCodec.PolicyDigest(signed)))
            throw new AgentPolicyLifecycleException("Stored policy digest is invalid.");
        return new(claims, signed, digest, stage, canary, approvals, updatedAt, updatedBy);
    }

    private static async Task Touch(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, string policyId, DateTimeOffset now, string subject,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            UPDATE certael_agent_policies SET updated_at=$3, updated_by=$4
            WHERE tenant_id=$1 AND policy_id=$2
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(policyId);
        command.Parameters.AddWithValue(now); command.Parameters.AddWithValue(subject);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task SetTenant(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static int CanaryBucket(string assignmentKey)
    {
        if (string.IsNullOrWhiteSpace(assignmentKey) || assignmentKey.Length > 512)
            throw new AgentPolicyLifecycleException("Canary assignment key is invalid.");
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(assignmentKey));
        return (int)(BinaryPrimitives.ReadUInt32BigEndian(digest) % 100);
    }

    private static void ValidateStage(AgentPolicyDeploymentStage stage, int canaryPercentage)
    {
        if (stage is AgentPolicyDeploymentStage.Draft or AgentPolicyDeploymentStage.Retired)
            throw new AgentPolicyLifecycleException("Use add or retire for this stage.");
        if (stage == AgentPolicyDeploymentStage.Canary && canaryPercentage is < 1 or > 99)
            throw new AgentPolicyLifecycleException("Canary percentage must be between 1 and 99.");
        if (stage != AgentPolicyDeploymentStage.Canary && canaryPercentage != 0)
            throw new AgentPolicyLifecycleException("Canary percentage only applies to canary stage.");
    }

    private static string Subject(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && !value.Any(char.IsControl) ? value
        : throw new AgentPolicyLifecycleException("Operator subject is invalid.");
}
