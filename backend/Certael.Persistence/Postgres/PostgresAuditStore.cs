using Certael.Server.Audit;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresAuditStore(NpgsqlDataSource dataSource) : IAuditStore
{
    public async ValueTask AppendAsync(AuditEvent value, CancellationToken cancellationToken)
    {
        AuditEventValidator.Validate(value);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, value.TenantId, cancellationToken);
        const string sql = """
            INSERT INTO certael_audit(audit_id,tenant_id,environment_id,operator_subject,operation,
              resource_type,resource_id,reason,before_digest,after_digest,request_id,occurred_at,succeeded,
              source_network,workload_identity)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(value.AuditId); command.Parameters.AddWithValue(value.TenantId);
        command.Parameters.AddWithValue(value.EnvironmentId); command.Parameters.AddWithValue(value.OperatorSubject);
        command.Parameters.AddWithValue(value.Operation); command.Parameters.AddWithValue(value.ResourceType);
        command.Parameters.AddWithValue(value.ResourceId); command.Parameters.AddWithValue(value.Reason);
        command.Parameters.AddWithValue((object?)value.BeforeDigest ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)value.AfterDigest ?? DBNull.Value);
        command.Parameters.AddWithValue(value.RequestId); command.Parameters.AddWithValue(value.OccurredAt);
        command.Parameters.AddWithValue(value.Succeeded);
        command.Parameters.AddWithValue((object?)value.SourceNetwork ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)value.WorkloadIdentity ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<IReadOnlyList<AuditEvent>> RecentAsync(string tenantId, string environmentId,
        int maximum, CancellationToken cancellationToken)
    {
        if (maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximum));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            SELECT audit_id,tenant_id,environment_id,operator_subject,operation,resource_type,
              resource_id,reason,before_digest,after_digest,request_id,occurred_at,succeeded
              ,source_network,workload_identity
            FROM certael_audit WHERE tenant_id=$1 AND environment_id=$2
            ORDER BY occurred_at DESC LIMIT $3
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(environmentId);
        command.Parameters.AddWithValue(maximum); var events = new List<AuditEvent>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) events.Add(new(reader.GetGuid(0), reader.GetString(1),
            reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6),
            reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8), reader.IsDBNull(9) ? null : reader.GetString(9),
            reader.GetString(10), reader.GetFieldValue<DateTimeOffset>(11), reader.GetBoolean(12),
            reader.IsDBNull(13) ? null : reader.GetString(13),
            reader.IsDBNull(14) ? null : reader.GetString(14)));
        await reader.DisposeAsync(); await transaction.CommitAsync(cancellationToken); return events;
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId); await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
