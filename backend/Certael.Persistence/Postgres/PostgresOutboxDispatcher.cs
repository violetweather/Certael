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

public sealed record PostgresOutboxDispatcherOptions
{
    public TimeSpan LeaseDuration { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan InitialRetryDelay { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MaximumRetryDelay { get; init; } = TimeSpan.FromMinutes(5);
    public int MaximumAttempts { get; init; } = 12;
}

public sealed record OutboxDispatchResult(int Claimed, int Published, int Retried, int DeadLettered);

/// <summary>
/// Publishes at least once. Consumers must deduplicate by EventId. Rows are
/// claimed with SKIP LOCKED so replicas can dispatch concurrently.
/// </summary>
public sealed class PostgresOutboxDispatcher
{
    private const int MaximumStoredErrorLength = 512;
    private readonly NpgsqlDataSource _dataSource;
    private readonly IOutboxPublisher _publisher;
    private readonly string _tenantId;
    private readonly string _leaseOwner;
    private readonly PostgresOutboxDispatcherOptions _options;

    public PostgresOutboxDispatcher(
        NpgsqlDataSource dataSource,
        IOutboxPublisher publisher,
        string tenantId,
        PostgresOutboxDispatcherOptions? options = null,
        string? leaseOwner = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        _dataSource = dataSource;
        _publisher = publisher;
        _tenantId = tenantId;
        _options = options ?? new PostgresOutboxDispatcherOptions();
        _leaseOwner = leaseOwner ?? $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid():N}";

        if (_options.LeaseDuration <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(options));
        if (_options.InitialRetryDelay <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(options));
        if (_options.MaximumRetryDelay < _options.InitialRetryDelay) throw new ArgumentOutOfRangeException(nameof(options));
        if (_options.MaximumAttempts < 1) throw new ArgumentOutOfRangeException(nameof(options));
    }

    public async Task<int> DispatchBatchAsync(int batchSize, CancellationToken cancellationToken = default)
        => (await DispatchBatchDetailedAsync(batchSize, cancellationToken)).Claimed;

    public async Task<OutboxDispatchResult> DispatchBatchDetailedAsync(
        int batchSize, CancellationToken cancellationToken = default)
    {
        if (batchSize is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(batchSize));
        IReadOnlyList<ClaimedMessage> messages = await ClaimBatchAsync(batchSize, cancellationToken);
        int published = 0;
        int retried = 0;
        int deadLettered = 0;
        foreach (ClaimedMessage claimed in messages)
        {
            try
            {
                await _publisher.PublishAsync(claimed.Message, cancellationToken);
                await MarkPublishedAsync(claimed.Message.EventId, cancellationToken);
                published++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                await ScheduleFailureAsync(claimed, exception, cancellationToken);
                if (claimed.Attempt >= _options.MaximumAttempts) deadLettered++;
                else retried++;
            }
        }

        return new OutboxDispatchResult(messages.Count, published, retried, deadLettered);
    }

    private async Task<IReadOnlyList<ClaimedMessage>> ClaimBatchAsync(int batchSize, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, cancellationToken);
        const string claim = """
            WITH candidates AS (
                SELECT outbox_id
                FROM certael_outbox
                WHERE tenant_id = $1
                  AND (
                    (delivery_state IN ('pending', 'retry') AND next_attempt_at <= now())
                    OR (delivery_state = 'leased' AND leased_until <= now())
                  )
                ORDER BY occurred_at, outbox_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            UPDATE certael_outbox AS outbox
            SET delivery_state = 'leased', lease_owner = $3,
                leased_until = now() + $4, attempts = attempts + 1,
                last_error = NULL
            FROM candidates
            WHERE outbox.outbox_id = candidates.outbox_id
            RETURNING outbox.outbox_id, outbox.tenant_id, outbox.game_id,
                      outbox.environment_id, outbox.session_id, outbox.action_id,
                      outbox.event_type, outbox.schema_version, outbox.payload,
                      outbox.occurred_at, outbox.attempts
            """;
        var messages = new List<ClaimedMessage>(batchSize);
        await using (var command = new NpgsqlCommand(claim, connection, transaction))
        {
            command.Parameters.AddWithValue(_tenantId);
            command.Parameters.AddWithValue(batchSize);
            command.Parameters.AddWithValue(_leaseOwner);
            command.Parameters.AddWithValue(_options.LeaseDuration);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var message = new OutboxMessage(
                    reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetGuid(5), reader.GetString(6), reader.GetInt32(7),
                    reader.GetFieldValue<byte[]>(8), reader.GetFieldValue<DateTimeOffset>(9));
                messages.Add(new ClaimedMessage(message, reader.GetInt32(10)));
            }
        }
        await transaction.CommitAsync(cancellationToken);
        return messages;
    }

    private async Task MarkPublishedAsync(Guid eventId, CancellationToken cancellationToken)
    {
        await ExecuteTenantUpdateAsync(
            """
            UPDATE certael_outbox
            SET delivery_state = 'published', published_at = now(),
                lease_owner = NULL, leased_until = NULL, last_error = NULL
            WHERE outbox_id = $1 AND tenant_id = $2
              AND delivery_state = 'leased' AND lease_owner = $3
            """,
            command =>
            {
                command.Parameters.AddWithValue(eventId);
                command.Parameters.AddWithValue(_tenantId);
                command.Parameters.AddWithValue(_leaseOwner);
            }, cancellationToken);
    }

    private async Task ScheduleFailureAsync(
        ClaimedMessage claimed, Exception exception, CancellationToken cancellationToken)
    {
        bool deadLetter = claimed.Attempt >= _options.MaximumAttempts;
        TimeSpan retryDelay = CalculateRetryDelay(claimed.Attempt);
        string error = SanitizeError(exception);
        const string sql = """
            UPDATE certael_outbox
            SET delivery_state = CASE WHEN $4 THEN 'dead_letter' ELSE 'retry' END,
                next_attempt_at = CASE WHEN $4 THEN next_attempt_at ELSE now() + $5 END,
                dead_lettered_at = CASE WHEN $4 THEN now() ELSE NULL END,
                lease_owner = NULL, leased_until = NULL, last_error = $6
            WHERE outbox_id = $1 AND tenant_id = $2
              AND delivery_state = 'leased' AND lease_owner = $3
            """;
        await ExecuteTenantUpdateAsync(sql, command =>
        {
            command.Parameters.AddWithValue(claimed.Message.EventId);
            command.Parameters.AddWithValue(_tenantId);
            command.Parameters.AddWithValue(_leaseOwner);
            command.Parameters.AddWithValue(deadLetter);
            command.Parameters.AddWithValue(retryDelay);
            command.Parameters.AddWithValue(error);
        }, cancellationToken);
    }

    private async Task ExecuteTenantUpdateAsync(
        string sql, Action<NpgsqlCommand> addParameters, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        addParameters(command);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private async Task SetTenantAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var tenant = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        tenant.Parameters.AddWithValue(_tenantId);
        await tenant.ExecuteNonQueryAsync(cancellationToken);
    }

    private TimeSpan CalculateRetryDelay(int attempt)
    {
        double multiplier = Math.Pow(2, Math.Min(attempt - 1, 30));
        double ticks = Math.Min(
            _options.InitialRetryDelay.Ticks * multiplier,
            _options.MaximumRetryDelay.Ticks);
        return TimeSpan.FromTicks((long)ticks);
    }

    private static string SanitizeError(Exception exception)
    {
        string value = exception.GetType().Name;
        return value.Length <= MaximumStoredErrorLength ? value : value[..MaximumStoredErrorLength];
    }

    private sealed record ClaimedMessage(OutboxMessage Message, int Attempt);
}
