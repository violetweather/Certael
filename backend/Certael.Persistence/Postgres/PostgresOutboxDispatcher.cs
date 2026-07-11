using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed record OutboxMessage(
    Guid EventId, string TenantId, string GameId, string EnvironmentId,
    string SessionId, Guid ActionId, string EventType, int SchemaVersion,
    byte[] Payload, DateTimeOffset OccurredAt);

public interface IOutboxPublisher
{
    ValueTask PublishAsync(OutboxMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// Publishes at least once. Consumers must deduplicate by EventId. Rows are
/// claimed with SKIP LOCKED so replicas can dispatch concurrently.
/// </summary>
public sealed class PostgresOutboxDispatcher(NpgsqlDataSource dataSource, IOutboxPublisher publisher)
{
    public async Task<int> DispatchBatchAsync(int batchSize, CancellationToken cancellationToken = default)
    {
        if (batchSize is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(batchSize));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        const string select = """
            SELECT outbox_id, tenant_id, game_id, environment_id, session_id, action_id,
                   event_type, schema_version, payload, occurred_at
            FROM certael_outbox WHERE published_at IS NULL
            ORDER BY occurred_at, outbox_id FOR UPDATE SKIP LOCKED LIMIT $1
            """;
        var messages = new List<OutboxMessage>(batchSize);
        await using (var command = new NpgsqlCommand(select, connection, transaction))
        {
            command.Parameters.AddWithValue(batchSize);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                messages.Add(new OutboxMessage(reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetString(4), reader.GetGuid(5), reader.GetString(6),
                    reader.GetInt32(7), reader.GetFieldValue<byte[]>(8), reader.GetFieldValue<DateTimeOffset>(9)));
        }
        foreach (OutboxMessage message in messages)
        {
            await publisher.PublishAsync(message, cancellationToken);
            await using var update = new NpgsqlCommand(
                "UPDATE certael_outbox SET published_at=now(), attempts=attempts+1 WHERE outbox_id=$1",
                connection, transaction);
            update.Parameters.AddWithValue(message.EventId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return messages.Count;
    }
}
