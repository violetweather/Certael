using System.Text.Json;
using Certael.Server.Actions;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresActionResultStore(NpgsqlDataSource dataSource) : IActionResultStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask<ActionResult<TResponse>?> FindAsync<TResponse>(string tenantId, string sessionId,
        Guid actionId, CancellationToken cancellationToken)
    {
        const string sql = "SELECT response_type, result FROM certael_action_results WHERE tenant_id=$1 AND session_id=$2 AND action_id=$3 AND status='completed'";
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(actionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        string expected = typeof(TResponse).AssemblyQualifiedName
            ?? throw new InvalidOperationException("Response type has no stable name.");
        if (!string.Equals(reader.GetString(0), expected, StringComparison.Ordinal))
            throw new InvalidOperationException("Stored response type does not match the requested action contract.");
        ActionResult<TResponse> result = JsonSerializer.Deserialize<ActionResult<TResponse>>(reader.GetString(1), Json)
            ?? throw new InvalidOperationException("Stored action result is invalid.");
        await reader.DisposeAsync(); await transaction.CommitAsync(cancellationToken); return result;
    }

    public async ValueTask StoreAsync<TResponse>(string tenantId, string sessionId, ActionResult<TResponse> result,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_action_results(tenant_id, session_id, action_id, response_type, result, status)
            VALUES ($1,$2,$3,$4,$5,'completed') ON CONFLICT (session_id, action_id) DO NOTHING
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(result.ActionId);
        command.Parameters.AddWithValue(typeof(TResponse).AssemblyQualifiedName
            ?? throw new InvalidOperationException("Response type has no stable name."));
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(result, Json));
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId); await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
