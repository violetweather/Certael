using Certael.Server.Agent;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresAgentBuildRegistry(
    NpgsqlDataSource dataSource,
    TimeProvider timeProvider) : IAgentBuildRegistry, IAgentBuildAdministration
{
    public async ValueTask<ApprovedAgentBuild> RegisterAsync(string tenantId, string gameId,
        string environmentId, string buildId, string operatorSubject,
        CancellationToken cancellationToken)
    {
        InMemoryAgentBuildRegistry.Validate(tenantId, gameId, environmentId, buildId,
            operatorSubject);
        DateTimeOffset now = timeProvider.GetUtcNow();
        await using NpgsqlConnection connection =
            await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction =
            await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_agent_builds(tenant_id, game_id, environment_id, build_id,
              registered_at, registered_by) VALUES($1,$2,$3,$4,$5,$6)
            """, connection, transaction);
        object[] values = [tenantId, gameId, environmentId, buildId, now, operatorSubject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        try { await command.ExecuteNonQueryAsync(cancellationToken); }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        { throw new AgentBuildRegistryException("Build is already registered."); }
        await transaction.CommitAsync(cancellationToken);
        return new(tenantId, gameId, environmentId, buildId, now, operatorSubject);
    }

    public async ValueTask<bool> RevokeAsync(string tenantId, string gameId,
        string environmentId, string buildId, string operatorSubject,
        CancellationToken cancellationToken)
    {
        InMemoryAgentBuildRegistry.Validate(tenantId, gameId, environmentId, buildId,
            operatorSubject);
        await using NpgsqlConnection connection =
            await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction =
            await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE certael_agent_builds SET revoked_at=$5, revoked_by=$6
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND build_id=$4
              AND revoked_at IS NULL
            """, connection, transaction);
        object[] values = [tenantId, gameId, environmentId, buildId,
            timeProvider.GetUtcNow(), operatorSubject];
        foreach (object value in values) command.Parameters.AddWithValue(value);
        bool changed = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    public async ValueTask<bool> IsApprovedAsync(string tenantId, string gameId,
        string environmentId, string buildId, CancellationToken cancellationToken)
    {
        InMemoryAgentBuildRegistry.Validate(tenantId, gameId, environmentId, buildId,
            "registry-reader");
        await using NpgsqlConnection connection =
            await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction =
            await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS(SELECT 1 FROM certael_agent_builds
              WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND build_id=$4
                AND revoked_at IS NULL)
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId); command.Parameters.AddWithValue(buildId);
        bool approved = (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
        await transaction.CommitAsync(cancellationToken);
        return approved;
    }

    private static async Task SetTenant(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
