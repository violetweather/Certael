using Certael.Server.Actions;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresSessionStore(NpgsqlDataSource dataSource) : ISessionAuthorizationStore,
    ISessionAuthorizationWriter, ISessionAdministrationStore
{
    public async ValueTask<SessionAuthorization?> FindAsync(string tenantId, string sessionId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT session_id, tenant_id, game_id, environment_id, player_subject, match_id,
                   authoritative_server_id, build_id, expires_at, minimum_sequence,
                   maximum_sequence, ephemeral_public_key, absolute_expires_at,
                   revoked_at, signing_key_id, protection_profile_id,
                   protocol_minimum, protocol_maximum
            FROM certael_sessions WHERE tenant_id = $1 AND session_id = $2
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(sessionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var result = new SessionAuthorization(
            reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
            reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7),
            reader.GetFieldValue<DateTimeOffset>(8), checked((ulong)reader.GetDecimal(9)),
            checked((ulong)reader.GetDecimal(10)), reader.GetFieldValue<byte[]>(11),
            reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12),
            reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13), reader.GetString(14),
            reader.GetString(15), checked((uint)reader.GetInt32(16)), checked((uint)reader.GetInt32(17)));
        await reader.DisposeAsync(); await transaction.CommitAsync(cancellationToken); return result;
    }

    public async ValueTask CreateAsync(SessionAuthorization session, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_sessions(session_id, tenant_id, game_id, environment_id,
              player_subject, match_id, authoritative_server_id, build_id, expires_at,
              minimum_sequence, maximum_sequence, ephemeral_public_key,
              absolute_expires_at, revoked_at, signing_key_id, protection_profile_id,
              protocol_minimum, protocol_maximum)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, session.TenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(session.SessionId); command.Parameters.AddWithValue(session.TenantId);
        command.Parameters.AddWithValue(session.GameId); command.Parameters.AddWithValue(session.EnvironmentId);
        command.Parameters.AddWithValue(session.PlayerSubject); command.Parameters.AddWithValue(session.MatchId);
        command.Parameters.AddWithValue(session.AuthoritativeServerId); command.Parameters.AddWithValue(session.BuildId);
        command.Parameters.AddWithValue(session.ExpiresAt); command.Parameters.AddWithValue((decimal)session.MinimumSequence);
        command.Parameters.AddWithValue((decimal)session.MaximumSequence);
        command.Parameters.AddWithValue(session.EphemeralPublicKey.ToArray());
        command.Parameters.AddWithValue((object?)session.AbsoluteExpiresAt ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)session.RevokedAt ?? DBNull.Value);
        command.Parameters.AddWithValue(session.SigningKeyId);
        command.Parameters.AddWithValue(session.ProtectionProfileId);
        command.Parameters.AddWithValue(checked((int)session.ProtocolMinimum));
        command.Parameters.AddWithValue(checked((int)session.ProtocolMaximum));
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<bool> RenewAsync(string tenantId, string sessionId, string authoritativeServerId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE certael_sessions SET expires_at=$3
            WHERE session_id=$1 AND authoritative_server_id=$2 AND tenant_id=$4 AND revoked_at IS NULL
              AND expires_at > now() - interval '30 seconds'
              AND (absolute_expires_at IS NULL OR absolute_expires_at >= $3)
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(authoritativeServerId);
        command.Parameters.AddWithValue(expiresAt);
        command.Parameters.AddWithValue(tenantId);
        bool updated = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        await transaction.CommitAsync(cancellationToken); return updated;
    }

    public async ValueTask<bool> RevokeAsync(string tenantId, string sessionId, string authoritativeServerId,
        DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE certael_sessions SET revoked_at=COALESCE(revoked_at,$3)
            WHERE session_id=$1 AND authoritative_server_id=$2 AND tenant_id=$4
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(sessionId); command.Parameters.AddWithValue(authoritativeServerId);
        command.Parameters.AddWithValue(revokedAt);
        command.Parameters.AddWithValue(tenantId);
        bool updated = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        await transaction.CommitAsync(cancellationToken); return updated;
    }

    public async ValueTask<int> RevokeMatchingAsync(SessionRevocationSelector selector,
        DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE certael_sessions SET revoked_at=$7
            WHERE tenant_id=$1 AND environment_id=$2 AND revoked_at IS NULL
              AND ($3::text IS NULL OR game_id=$3)
              AND ($4::text IS NULL OR build_id=$4)
              AND ($5::text IS NULL OR signing_key_id=$5)
              AND ($6::text IS NULL OR authoritative_server_id=$6)
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, selector.TenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(selector.TenantId);
        command.Parameters.AddWithValue(selector.EnvironmentId);
        command.Parameters.AddWithValue((object?)selector.GameId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)selector.BuildId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)selector.SigningKeyId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)selector.AuthoritativeServerId ?? DBNull.Value);
        command.Parameters.AddWithValue(revokedAt);
        int updated = await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return updated;
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
