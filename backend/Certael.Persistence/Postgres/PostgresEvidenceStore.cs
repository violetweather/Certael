using System.Text.Json;
using Certael.Server.Evidence;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresEvidenceStore(
    NpgsqlDataSource dataSource,
    TimeSpan retention) : IEvidenceStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask SaveAsync(EvidenceBundle bundle, CancellationToken cancellationToken)
    {
        if (retention <= TimeSpan.Zero || retention > TimeSpan.FromDays(3660))
            throw new InvalidOperationException("Evidence retention is invalid.");
        if (bundle.Findings.Any(value => value.TenantId != bundle.Verdict.TenantId))
            throw new InvalidOperationException("Cross-tenant evidence is prohibited.");
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, bundle.Verdict.TenantId, cancellationToken);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using (var purge = new NpgsqlCommand(
            "DELETE FROM certael_evidence WHERE tenant_id=$1 AND expires_at <= $2",
            connection, transaction))
        {
            purge.Parameters.AddWithValue(bundle.Verdict.TenantId);
            purge.Parameters.AddWithValue(now);
            await purge.ExecuteNonQueryAsync(cancellationToken);
        }
        const string sql = """
            INSERT INTO certael_evidence(tenant_id, verdict_id, game_id, environment_id,
              player_subject, bundle, replay_digest, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(bundle.Verdict.TenantId); command.Parameters.AddWithValue(bundle.Verdict.VerdictId);
        command.Parameters.AddWithValue(bundle.Verdict.GameId); command.Parameters.AddWithValue(bundle.Verdict.EnvironmentId);
        command.Parameters.AddWithValue(bundle.Verdict.PlayerSubject);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(bundle, Json));
        command.Parameters.AddWithValue(bundle.ReplayDigest);
        DateTimeOffset expiresAt = now + RetentionFor(bundle, retention);
        command.Parameters.AddWithValue(expiresAt);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await SaveNormalizedAsync(connection, transaction, bundle, expiresAt, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public static TimeSpan RetentionFor(EvidenceBundle bundle, TimeSpan configured)
    {
        if (configured <= TimeSpan.Zero || configured > TimeSpan.FromDays(3660))
            throw new InvalidOperationException("Evidence retention is invalid.");
        bool containsAdvisory = bundle.Findings.Any(finding =>
            finding.Trust != FindingTrust.Authoritative);
        return containsAdvisory && configured > TimeSpan.FromDays(30)
            ? TimeSpan.FromDays(30) : configured;
    }

    public async ValueTask<EvidenceBundle?> FindAsync(string tenantId, Guid verdictId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT bundle FROM certael_evidence WHERE tenant_id=$1 AND verdict_id=$2 AND expires_at > now()",
            connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(verdictId);
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return value is string json ? JsonSerializer.Deserialize<EvidenceBundle>(json, Json) : null;
    }

    public async ValueTask DeletePlayerAsync(string tenantId, string environmentId,
        string playerSubject, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        string[] statements =
        [
            "DELETE FROM certael_evidence WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3",
            "DELETE FROM certael_verdicts WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3",
            "DELETE FROM certael_findings WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3",
        ];
        foreach (string sql in statements)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task SaveNormalizedAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, EvidenceBundle bundle, DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        const string verdictSql = """
            INSERT INTO certael_verdicts(tenant_id, verdict_id, game_id, environment_id,
              session_id, player_subject, risk_score, confidence, recommendation,
              rule_versions, replay_digest, bundle, created_at, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            """;
        await using (var verdict = new NpgsqlCommand(verdictSql, connection, transaction))
        {
            verdict.Parameters.AddWithValue(bundle.Verdict.TenantId);
            verdict.Parameters.AddWithValue(bundle.Verdict.VerdictId);
            verdict.Parameters.AddWithValue(bundle.Verdict.GameId);
            verdict.Parameters.AddWithValue(bundle.Verdict.EnvironmentId);
            verdict.Parameters.AddWithValue(bundle.Verdict.SessionId);
            verdict.Parameters.AddWithValue(bundle.Verdict.PlayerSubject);
            verdict.Parameters.AddWithValue(bundle.Verdict.RiskScore);
            verdict.Parameters.AddWithValue(bundle.Verdict.Confidence);
            verdict.Parameters.AddWithValue(bundle.Verdict.Recommendation.ToString());
            verdict.Parameters.AddWithValue(bundle.Verdict.RuleVersions.ToArray());
            verdict.Parameters.AddWithValue(bundle.ReplayDigest);
            verdict.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(bundle, Json));
            verdict.Parameters.AddWithValue(bundle.Verdict.CreatedAt);
            verdict.Parameters.AddWithValue(expiresAt);
            await verdict.ExecuteNonQueryAsync(cancellationToken);
        }

        const string findingSql = """
            INSERT INTO certael_findings(tenant_id, finding_id, game_id, environment_id,
              session_id, player_subject, rule_id, rule_version, rule_pack_digest,
              action_id, signal_family, trust, risk_contribution, confidence, fields,
              observed_at, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
            """;
        const string linkSql = """
            INSERT INTO certael_verdict_findings(tenant_id, verdict_id, finding_id)
            VALUES ($1,$2,$3)
            """;
        foreach (Finding findingValue in bundle.Findings)
        {
            await using (var finding = new NpgsqlCommand(findingSql, connection, transaction))
            {
                finding.Parameters.AddWithValue(findingValue.TenantId);
                finding.Parameters.AddWithValue(findingValue.FindingId);
                finding.Parameters.AddWithValue(findingValue.GameId);
                finding.Parameters.AddWithValue(findingValue.EnvironmentId);
                finding.Parameters.AddWithValue(findingValue.SessionId);
                finding.Parameters.AddWithValue(findingValue.PlayerSubject);
                finding.Parameters.AddWithValue(findingValue.RuleId);
                finding.Parameters.AddWithValue(findingValue.RuleVersion);
                finding.Parameters.AddWithValue(findingValue.RulePackDigest);
                finding.Parameters.AddWithValue((object?)findingValue.ActionId ?? DBNull.Value);
                finding.Parameters.AddWithValue(findingValue.SignalFamily.ToString());
                finding.Parameters.AddWithValue(findingValue.Trust.ToString());
                finding.Parameters.AddWithValue(findingValue.RiskContribution);
                finding.Parameters.AddWithValue(findingValue.Confidence);
                finding.Parameters.AddWithValue(NpgsqlDbType.Jsonb,
                    JsonSerializer.Serialize(findingValue.Fields, Json));
                finding.Parameters.AddWithValue(findingValue.ObservedAt);
                finding.Parameters.AddWithValue(expiresAt);
                await finding.ExecuteNonQueryAsync(cancellationToken);
            }
            await using var link = new NpgsqlCommand(linkSql, connection, transaction);
            link.Parameters.AddWithValue(bundle.Verdict.TenantId);
            link.Parameters.AddWithValue(bundle.Verdict.VerdictId);
            link.Parameters.AddWithValue(findingValue.FindingId);
            await link.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
