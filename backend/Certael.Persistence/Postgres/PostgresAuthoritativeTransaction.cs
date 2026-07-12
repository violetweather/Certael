using Certael.Server.Actions;
using Npgsql;
using NpgsqlTypes;
using System.Text.Json;

namespace Certael.Persistence.Postgres;

/// <summary>
/// Owns the same PostgreSQL transaction used by game-state mutations and the
/// Certael outbox, so accepted state and its authoritative event commit atomically.
/// </summary>
public sealed class PostgresAuthoritativeTransaction<TState> : IAuthoritativeTransaction<TState>
{
    private readonly NpgsqlConnection _connection;
    private readonly NpgsqlTransaction _transaction;
    private readonly string _tenantId;
    private readonly string _gameId;
    private readonly string _environmentId;
    private readonly string _sessionId;
    private readonly List<AuthoritativeEvent> _events = [];
    private bool _completed;
    private Guid? _reservedAction;
    private bool _resultStaged;
    private bool _tenantSet;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public PostgresAuthoritativeTransaction(NpgsqlConnection connection, NpgsqlTransaction transaction,
        TState current, ulong revision, string tenantId, string gameId, string environmentId, string sessionId)
    {
        _connection = connection; _transaction = transaction; Current = current; Revision = revision;
        _tenantId = tenantId; _gameId = gameId; _environmentId = environmentId; _sessionId = sessionId;
    }

    public TState Current { get; }
    public ulong Revision { get; }
    public NpgsqlConnection Connection => _connection;
    public NpgsqlTransaction Transaction => _transaction;

    public async ValueTask<ActionReservation<TResponse>> ReserveActionAsync<TResponse>(Guid actionId,
        CancellationToken cancellationToken)
    {
        if (_completed || _reservedAction is not null)
            throw new InvalidOperationException("Only one action may be reserved per transaction.");
        await EnsureTenantAsync(cancellationToken);
        const string insert = """
            INSERT INTO certael_action_results(tenant_id, session_id, action_id, response_type, result, status)
            VALUES ($1,$2,$3,$4,NULL,'processing') ON CONFLICT (session_id, action_id) DO NOTHING
            """;
        string responseType = typeof(TResponse).AssemblyQualifiedName
            ?? throw new InvalidOperationException("Response type has no stable name.");
        await using (var command = new NpgsqlCommand(insert, _connection, _transaction))
        {
            command.Parameters.AddWithValue(_tenantId); command.Parameters.AddWithValue(_sessionId);
            command.Parameters.AddWithValue(actionId); command.Parameters.AddWithValue(responseType);
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 1)
            { _reservedAction = actionId; return ActionReservation<TResponse>.New(); }
        }
        await using var existing = new NpgsqlCommand(
            "SELECT response_type, result, status FROM certael_action_results WHERE tenant_id=$1 AND session_id=$2 AND action_id=$3",
            _connection, _transaction);
        existing.Parameters.AddWithValue(_tenantId); existing.Parameters.AddWithValue(_sessionId); existing.Parameters.AddWithValue(actionId);
        await using NpgsqlDataReader reader = await existing.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken) || reader.GetString(2) != "completed" || reader.IsDBNull(1))
            throw new InvalidOperationException("Existing action reservation is incomplete.");
        if (!string.Equals(reader.GetString(0), responseType, StringComparison.Ordinal))
            throw new InvalidOperationException("Action response type mismatch.");
        ActionResult<TResponse> result = JsonSerializer.Deserialize<ActionResult<TResponse>>(reader.GetString(1), Json)
            ?? throw new InvalidOperationException("Existing action result is invalid.");
        return ActionReservation<TResponse>.Existing(result);
    }

    public async ValueTask StageActionResultAsync<TResponse>(ActionResult<TResponse> result,
        CancellationToken cancellationToken)
    {
        if (_completed || _reservedAction != result.ActionId || _resultStaged)
            throw new InvalidOperationException("Action result does not match the active reservation.");
        const string update = """
            UPDATE certael_action_results SET result=$3, status='completed'
            WHERE session_id=$1 AND action_id=$2 AND status='processing'
            """;
        await using var command = new NpgsqlCommand(update, _connection, _transaction);
        command.Parameters.AddWithValue(_sessionId); command.Parameters.AddWithValue(result.ActionId);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(result, Json));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException("Failed to stage the authoritative action result.");
        _resultStaged = true;
    }

    public void EnqueueAuthoritativeEvent(AuthoritativeEvent authoritativeEvent)
    {
        if (_completed) throw new InvalidOperationException("Transaction is complete.");
        if (_events.Any(value => value.EventId == authoritativeEvent.EventId))
            throw new InvalidOperationException("Duplicate authoritative event ID.");
        _events.Add(authoritativeEvent);
    }

    public async ValueTask<(TState State, ulong Revision)> CommitAsync(CancellationToken cancellationToken)
    {
        if (_completed) throw new InvalidOperationException("Transaction is complete.");
        if (_events.Count == 0 || !_resultStaged)
            throw new InvalidOperationException("Accepted mutations require an outbox event and staged action result.");
        const string sql = """
            INSERT INTO certael_outbox(outbox_id, tenant_id, game_id, environment_id, session_id,
              action_id, event_type, schema_version, payload, occurred_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            """;
        foreach (AuthoritativeEvent item in _events)
        {
            await using var command = new NpgsqlCommand(sql, _connection, _transaction);
            command.Parameters.AddWithValue(item.EventId); command.Parameters.AddWithValue(_tenantId);
            command.Parameters.AddWithValue(_gameId); command.Parameters.AddWithValue(_environmentId);
            command.Parameters.AddWithValue(_sessionId); command.Parameters.AddWithValue(item.ActionId);
            command.Parameters.AddWithValue(item.EventType); command.Parameters.AddWithValue(checked((int)item.SchemaVersion));
            command.Parameters.AddWithValue(item.Payload.ToArray()); command.Parameters.AddWithValue(item.ServerTime);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await _transaction.CommitAsync(cancellationToken);
        _completed = true;
        return (Current, checked(Revision + 1));
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed) await _transaction.RollbackAsync();
        await _transaction.DisposeAsync();
        await _connection.DisposeAsync();
    }

    private async ValueTask EnsureTenantAsync(CancellationToken cancellationToken)
    {
        if (_tenantSet) return;
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id', $1, true)", _connection, _transaction);
        command.Parameters.AddWithValue(_tenantId); await command.ExecuteNonQueryAsync(cancellationToken);
        _tenantSet = true;
    }
}
