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
        command.Parameters.AddWithValue(bundle.ReplayDigest); command.Parameters.AddWithValue(DateTimeOffset.UtcNow + retention);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
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

    public async ValueTask DeletePlayerAsync(string tenantId, string playerSubject,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(
            "DELETE FROM certael_evidence WHERE tenant_id=$1 AND player_subject=$2", connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(playerSubject);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
