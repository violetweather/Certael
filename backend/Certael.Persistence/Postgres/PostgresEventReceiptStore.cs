using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresEventReceiptStore(NpgsqlDataSource dataSource)
{
    public async ValueTask<bool> ExistsAsync(string tenantId, string consumerName, Guid eventId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1 FROM certael_event_receipts
                WHERE tenant_id = $1 AND consumer_name = $2 AND event_id = $3
            )
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(consumerName);
        command.Parameters.AddWithValue(eventId);
        bool exists = (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
        await transaction.CommitAsync(cancellationToken);
        return exists;
    }

    public async ValueTask RecordAsync(string tenantId, string consumerName, Guid eventId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_event_receipts (tenant_id, consumer_name, event_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, consumer_name, event_id) DO NOTHING
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(consumerName);
        command.Parameters.AddWithValue(eventId);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async ValueTask SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
