using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed record OutboxDeadLetter(
    Guid EventId, string GameId, string EnvironmentId, string SessionId,
    Guid ActionId, string EventType, int SchemaVersion, int Attempts,
    string? SanitizedError, DateTimeOffset OccurredAt, DateTimeOffset DeadLetteredAt);

public sealed class PostgresOutboxAdministration(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<OutboxDeadLetter>> ListDeadLettersAsync(
        string tenantId, int maximum, CancellationToken cancellationToken = default)
    {
        if (maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximum));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            SELECT outbox_id, game_id, environment_id, session_id, action_id,
                   event_type, schema_version, attempts, last_error, occurred_at, dead_lettered_at
            FROM certael_outbox
            WHERE tenant_id = $1 AND delivery_state = 'dead_letter'
            ORDER BY dead_lettered_at DESC, outbox_id
            LIMIT $2
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(maximum);
        var results = new List<OutboxDeadLetter>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            results.Add(new OutboxDeadLetter(reader.GetGuid(0), reader.GetString(1),
                reader.GetString(2), reader.GetString(3), reader.GetGuid(4), reader.GetString(5),
                reader.GetInt32(6), reader.GetInt32(7), reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.GetFieldValue<DateTimeOffset>(9), reader.GetFieldValue<DateTimeOffset>(10)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return results;
    }

    public async Task<bool> ReplayAsync(
        string tenantId, Guid eventId, CancellationToken cancellationToken = default)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            UPDATE certael_outbox
            SET delivery_state = 'retry', attempts = 0, next_attempt_at = now(),
                lease_owner = NULL, leased_until = NULL, last_error = NULL, dead_lettered_at = NULL
            WHERE tenant_id = $1 AND outbox_id = $2 AND delivery_state = 'dead_letter'
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(eventId);
        bool changed = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    private static async Task SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
