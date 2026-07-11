using Certael.Server.Actions;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresSessionStore(NpgsqlDataSource dataSource) : ISessionAuthorizationStore, ISessionAuthorizationWriter
{
    public async ValueTask<SessionAuthorization?> FindAsync(string sessionId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT session_id, tenant_id, game_id, environment_id, player_subject, match_id,
                   authoritative_server_id, build_id, expires_at, minimum_sequence,
                   maximum_sequence, ephemeral_public_key
            FROM certael_sessions WHERE session_id = $1
            """;
        await using NpgsqlCommand command = dataSource.CreateCommand(sql);
        command.Parameters.AddWithValue(sessionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new SessionAuthorization(
            reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
            reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7),
            reader.GetFieldValue<DateTimeOffset>(8), checked((ulong)reader.GetDecimal(9)),
            checked((ulong)reader.GetDecimal(10)), reader.GetFieldValue<byte[]>(11));
    }

    public async ValueTask CreateAsync(SessionAuthorization session, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_sessions(session_id, tenant_id, game_id, environment_id,
              player_subject, match_id, authoritative_server_id, build_id, expires_at,
              minimum_sequence, maximum_sequence, ephemeral_public_key)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            """;
        await using NpgsqlCommand command = dataSource.CreateCommand(sql);
        command.Parameters.AddWithValue(session.SessionId); command.Parameters.AddWithValue(session.TenantId);
        command.Parameters.AddWithValue(session.GameId); command.Parameters.AddWithValue(session.EnvironmentId);
        command.Parameters.AddWithValue(session.PlayerSubject); command.Parameters.AddWithValue(session.MatchId);
        command.Parameters.AddWithValue(session.AuthoritativeServerId); command.Parameters.AddWithValue(session.BuildId);
        command.Parameters.AddWithValue(session.ExpiresAt); command.Parameters.AddWithValue((decimal)session.MinimumSequence);
        command.Parameters.AddWithValue((decimal)session.MaximumSequence);
        command.Parameters.AddWithValue(session.EphemeralPublicKey.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async ValueTask<bool> RenewAsync(string sessionId, string authoritativeServerId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE certael_sessions SET expires_at=$3
            WHERE session_id=$1 AND authoritative_server_id=$2 AND expires_at > now() - interval '30 seconds'
            """;
        await using NpgsqlCommand command = dataSource.CreateCommand(sql);
        command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(authoritativeServerId);
        command.Parameters.AddWithValue(expiresAt);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }
}
