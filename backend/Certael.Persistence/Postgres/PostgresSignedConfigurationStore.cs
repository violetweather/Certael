using System.Security.Cryptography;
using Certael.Server.Configuration;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresSignedConfigurationStore(
    NpgsqlDataSource dataSource,
    ISignedConfigurationVerifier verifier,
    TimeProvider timeProvider) : ISignedConfigurationAdministration
{
    public async ValueTask<SignedConfigurationDeployment> AddDraftAsync(
        SignedConfigurationArtifact artifact, string author, CancellationToken cancellationToken)
    {
        SignedConfigurationValidation.Validate(artifact);
        if (!verifier.Verify(artifact))
            throw new SignedConfigurationException("Configuration signature or canonical document is invalid.");
        string subject = SignedConfigurationValidation.Subject(author);
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, artifact.TenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_signed_configurations(tenant_id, artifact_kind, artifact_id,
              version, game_id, environment_id, canonical_document, digest, signature,
              signing_key_id, stage, canary_percentage, created_at, created_by, updated_at, updated_by)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,0,$11,$12,$11,$12)
            """, connection, transaction);
        object[] values = [artifact.TenantId, (int)artifact.Kind, artifact.ArtifactId,
            artifact.Version, artifact.GameId, artifact.EnvironmentId, artifact.CanonicalDocument,
            artifact.Digest, artifact.Signature, artifact.SigningKeyId, now, subject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        try { await command.ExecuteNonQueryAsync(cancellationToken); }
        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.UniqueViolation)
        { throw new SignedConfigurationException("Configuration version is immutable and already exists."); }
        await transaction.CommitAsync(cancellationToken);
        return new(artifact, SignedConfigurationStage.Draft, 0, [], now, subject);
    }

    public async ValueTask<SignedConfigurationDeployment> ApproveAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version, string approver,
        CancellationToken cancellationToken)
    {
        string subject = SignedConfigurationValidation.Subject(approver);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        SignedConfigurationDeployment current = await Read(connection, transaction, tenantId,
            kind, artifactId, version, true, cancellationToken);
        if (current.Stage == SignedConfigurationStage.Retired)
            throw new SignedConfigurationException("A retired configuration cannot be approved.");
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO certael_signed_configuration_approvals(tenant_id, artifact_kind,
              artifact_id, version, approver_subject, approved_at, artifact_digest)
            VALUES($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT(tenant_id, artifact_kind, artifact_id, version, approver_subject) DO NOTHING
            """, connection, transaction);
        object[] values = [tenantId, (int)kind, artifactId, version, subject, now,
            current.Artifact.Digest];
        foreach (object value in values) insert.Parameters.AddWithValue(value);
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await Touch(connection, transaction, tenantId, kind, artifactId, version, now, subject,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, kind, artifactId, version, cancellationToken);
    }

    public async ValueTask<SignedConfigurationDeployment> PromoteAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version,
        SignedConfigurationStage stage, int canaryPercentage, string operatorSubject,
        CancellationToken cancellationToken)
    {
        SignedConfigurationValidation.Stage(stage, canaryPercentage);
        string subject = SignedConfigurationValidation.Subject(operatorSubject);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        SignedConfigurationDeployment current = await Read(connection, transaction, tenantId,
            kind, artifactId, version, true, cancellationToken);
        EnsureVerified(current);
        int required = stage == SignedConfigurationStage.Enforced ? 2 : 1;
        if (current.Approvals.Select(value => value.ApproverSubject)
            .Distinct(StringComparer.Ordinal).Count() < required)
            throw new SignedConfigurationException($"{stage} requires {required} distinct approvals.");
        if (current.Approvals.Any(value => !CryptographicOperations.FixedTimeEquals(
            value.ArtifactDigest, current.Artifact.Digest)))
            throw new SignedConfigurationException("Approval digest does not match the artifact.");
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using (var update = new NpgsqlCommand("""
            UPDATE certael_signed_configurations SET stage=$5, canary_percentage=$6,
              updated_at=$7, updated_by=$8
            WHERE tenant_id=$1 AND artifact_kind=$2 AND artifact_id=$3 AND version=$4
            """, connection, transaction))
        {
            object[] values = [tenantId, (int)kind, artifactId, version, (int)stage,
                canaryPercentage, now, subject];
            foreach (object value in values) update.Parameters.AddWithValue(value);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        if (stage is SignedConfigurationStage.Canary or SignedConfigurationStage.Enforced)
            await Activate(connection, transaction, current.Artifact, subject, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, kind, artifactId, version, cancellationToken);
    }

    public async ValueTask<SignedConfigurationDeployment> RollbackAsync(string tenantId,
        SignedConfigurationKind kind, string gameId, string environmentId,
        string operatorSubject, CancellationToken cancellationToken)
    {
        string subject = SignedConfigurationValidation.Subject(operatorSubject);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var active = new NpgsqlCommand("""
            SELECT active_artifact_id, active_version, previous_artifact_id, previous_version
            FROM certael_signed_configuration_active
            WHERE tenant_id=$1 AND artifact_kind=$2 AND game_id=$3 AND environment_id=$4
            FOR UPDATE
            """, connection, transaction);
        active.Parameters.AddWithValue(tenantId); active.Parameters.AddWithValue((int)kind);
        active.Parameters.AddWithValue(gameId); active.Parameters.AddWithValue(environmentId);
        await using NpgsqlDataReader reader = await active.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken) || reader.IsDBNull(2) || reader.IsDBNull(3))
            throw new SignedConfigurationException("No prior configuration is available.");
        string currentId = reader.GetString(0), currentVersion = reader.GetString(1);
        string priorId = reader.GetString(2), priorVersion = reader.GetString(3);
        await reader.DisposeAsync();
        SignedConfigurationDeployment prior = await Read(connection, transaction, tenantId, kind,
            priorId, priorVersion, true, cancellationToken);
        EnsureVerified(prior);
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using (var update = new NpgsqlCommand("""
            UPDATE certael_signed_configuration_active
            SET active_artifact_id=$5, active_version=$6, previous_artifact_id=$7,
              previous_version=$8, updated_at=$9, updated_by=$10
            WHERE tenant_id=$1 AND artifact_kind=$2 AND game_id=$3 AND environment_id=$4
            """, connection, transaction))
        {
            object[] values = [tenantId, (int)kind, gameId, environmentId, priorId,
                priorVersion, currentId, currentVersion, now, subject];
            foreach (object value in values) update.Parameters.AddWithValue(value);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        await SetStage(connection, transaction, tenantId, kind, priorId, priorVersion,
            SignedConfigurationStage.Enforced, now, subject, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, kind, priorId, priorVersion, cancellationToken);
    }

    public async ValueTask<SignedConfigurationDeployment> RetireAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version, string operatorSubject,
        CancellationToken cancellationToken)
    {
        string subject = SignedConfigurationValidation.Subject(operatorSubject);
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await Read(connection, transaction, tenantId, kind, artifactId, version, true, cancellationToken);
        await SetStage(connection, transaction, tenantId, kind, artifactId, version,
            SignedConfigurationStage.Retired, now, subject, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(tenantId, kind, artifactId, version, cancellationToken);
    }

    public async ValueTask<SignedConfigurationDeployment> GetAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        SignedConfigurationDeployment result = await Read(connection, transaction, tenantId,
            kind, artifactId, version, false, cancellationToken);
        EnsureVerified(result);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private async Task<SignedConfigurationDeployment> Read(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, SignedConfigurationKind kind,
        string artifactId, string version, bool forUpdate, CancellationToken cancellationToken)
    {
        string sql = """
            SELECT game_id, environment_id, canonical_document, digest, signature,
              signing_key_id, stage, canary_percentage, updated_at, updated_by
            FROM certael_signed_configurations
            WHERE tenant_id=$1 AND artifact_kind=$2 AND artifact_id=$3 AND version=$4
            """ + (forUpdate ? " FOR UPDATE" : string.Empty);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue((int)kind);
        command.Parameters.AddWithValue(artifactId); command.Parameters.AddWithValue(version);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            throw new SignedConfigurationException("Configuration does not exist.");
        var artifact = new SignedConfigurationArtifact(kind, tenantId, artifactId, version,
            reader.GetString(0), reader.GetString(1), reader.GetFieldValue<byte[]>(2),
            reader.GetFieldValue<byte[]>(3), reader.GetFieldValue<byte[]>(4), reader.GetString(5));
        var deployment = new SignedConfigurationDeployment(artifact,
            (SignedConfigurationStage)reader.GetInt32(6), reader.GetInt32(7), [],
            reader.GetFieldValue<DateTimeOffset>(8), reader.GetString(9));
        await reader.DisposeAsync();
        var approvals = new List<SignedConfigurationApproval>();
        await using var approval = new NpgsqlCommand("""
            SELECT approver_subject, approved_at, artifact_digest
            FROM certael_signed_configuration_approvals
            WHERE tenant_id=$1 AND artifact_kind=$2 AND artifact_id=$3 AND version=$4
            ORDER BY approver_subject
            """, connection, transaction);
        approval.Parameters.AddWithValue(tenantId); approval.Parameters.AddWithValue((int)kind);
        approval.Parameters.AddWithValue(artifactId); approval.Parameters.AddWithValue(version);
        await using NpgsqlDataReader approvalsReader = await approval.ExecuteReaderAsync(cancellationToken);
        while (await approvalsReader.ReadAsync(cancellationToken))
            approvals.Add(new(approvalsReader.GetString(0),
                approvalsReader.GetFieldValue<DateTimeOffset>(1),
                approvalsReader.GetFieldValue<byte[]>(2)));
        return deployment with { Approvals = approvals };
    }

    private void EnsureVerified(SignedConfigurationDeployment deployment)
    {
        SignedConfigurationValidation.Validate(deployment.Artifact);
        if (!verifier.Verify(deployment.Artifact))
            throw new SignedConfigurationException("Stored configuration no longer verifies.");
    }

    private static async Task Activate(NpgsqlConnection connection, NpgsqlTransaction transaction,
        SignedConfigurationArtifact artifact, string subject, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_signed_configuration_active(tenant_id, artifact_kind, game_id,
              environment_id, active_artifact_id, active_version, updated_at, updated_by)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT(tenant_id, artifact_kind, game_id, environment_id) DO UPDATE SET
              previous_artifact_id=certael_signed_configuration_active.active_artifact_id,
              previous_version=certael_signed_configuration_active.active_version,
              active_artifact_id=EXCLUDED.active_artifact_id,
              active_version=EXCLUDED.active_version, updated_at=EXCLUDED.updated_at,
              updated_by=EXCLUDED.updated_by
            WHERE certael_signed_configuration_active.active_artifact_id <> EXCLUDED.active_artifact_id
               OR certael_signed_configuration_active.active_version <> EXCLUDED.active_version
            """, connection, transaction);
        object[] values = [artifact.TenantId, (int)artifact.Kind, artifact.GameId,
            artifact.EnvironmentId, artifact.ArtifactId, artifact.Version, now, subject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task SetStage(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, SignedConfigurationKind kind, string artifactId, string version,
        SignedConfigurationStage stage, DateTimeOffset now, string subject,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            UPDATE certael_signed_configurations SET stage=$5, canary_percentage=0,
              updated_at=$6, updated_by=$7
            WHERE tenant_id=$1 AND artifact_kind=$2 AND artifact_id=$3 AND version=$4
            """, connection, transaction);
        object[] values = [tenantId, (int)kind, artifactId, version, (int)stage, now, subject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static Task Touch(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, SignedConfigurationKind kind, string artifactId, string version,
        DateTimeOffset now, string subject, CancellationToken cancellationToken) =>
        SetStagePreserving(connection, transaction, tenantId, kind, artifactId, version, now,
            subject, cancellationToken);

    private static async Task SetStagePreserving(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, SignedConfigurationKind kind,
        string artifactId, string version, DateTimeOffset now, string subject,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            UPDATE certael_signed_configurations SET updated_at=$5, updated_by=$6
            WHERE tenant_id=$1 AND artifact_kind=$2 AND artifact_id=$3 AND version=$4
            """, connection, transaction);
        object[] values = [tenantId, (int)kind, artifactId, version, now, subject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
