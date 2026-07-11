using System.Text.Json;
using Certael.Server.Actions;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresActionResultStore(NpgsqlDataSource dataSource) : IActionResultStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask<ActionResult<TResponse>?> FindAsync<TResponse>(string sessionId,
        Guid actionId, CancellationToken cancellationToken)
    {
        const string sql = "SELECT response_type, result FROM certael_action_results WHERE session_id=$1 AND action_id=$2 AND status='completed'";
        await using NpgsqlCommand command = dataSource.CreateCommand(sql);
        command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(actionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        string expected = typeof(TResponse).AssemblyQualifiedName
            ?? throw new InvalidOperationException("Response type has no stable name.");
        if (!string.Equals(reader.GetString(0), expected, StringComparison.Ordinal))
            throw new InvalidOperationException("Stored response type does not match the requested action contract.");
        return JsonSerializer.Deserialize<ActionResult<TResponse>>(reader.GetString(1), Json)
            ?? throw new InvalidOperationException("Stored action result is invalid.");
    }

    public async ValueTask StoreAsync<TResponse>(string sessionId, ActionResult<TResponse> result,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_action_results(session_id, action_id, response_type, result, status)
            VALUES ($1,$2,$3,$4,'completed') ON CONFLICT (session_id, action_id) DO NOTHING
            """;
        await using NpgsqlCommand command = dataSource.CreateCommand(sql);
        command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(result.ActionId);
        command.Parameters.AddWithValue(typeof(TResponse).AssemblyQualifiedName
            ?? throw new InvalidOperationException("Response type has no stable name."));
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(result, Json));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
