using Certael.Server.Agent;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresAgentSessionStore(NpgsqlDataSource dataSource) : IAgentSessionStore
{
    public async ValueTask CreateAsync(VerifiedAgentSession session, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_agent_sessions(agent_session_id, tenant_id, game_id,
              environment_id, player_subject, match_id, build_id, agent_public_key,
              last_sequence, last_report_digest, expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, session.TenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(session.AgentSessionId);
        command.Parameters.AddWithValue(session.TenantId);
        command.Parameters.AddWithValue(session.GameId);
        command.Parameters.AddWithValue(session.EnvironmentId);
        command.Parameters.AddWithValue(session.PlayerSubject);
        command.Parameters.AddWithValue(session.MatchId);
        command.Parameters.AddWithValue(session.BuildId);
        command.Parameters.AddWithValue(session.AgentPublicKey);
        command.Parameters.AddWithValue((decimal)session.LastSequence);
        command.Parameters.AddWithValue(session.LastReportDigest);
        command.Parameters.AddWithValue(session.ExpiresAt);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<VerifiedAgentSession?> FindAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT agent_session_id, tenant_id, game_id, environment_id, player_subject,
              match_id, build_id, agent_public_key, last_sequence, last_report_digest, expires_at
            FROM certael_agent_sessions
            WHERE tenant_id=$1 AND agent_session_id=$2 AND revoked_at IS NULL
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(agentSessionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var result = new VerifiedAgentSession(reader.GetString(0), reader.GetString(1),
            reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5),
            reader.GetString(6), reader.GetFieldValue<byte[]>(7), checked((ulong)reader.GetDecimal(8)),
            reader.GetFieldValue<byte[]>(9), reader.GetFieldValue<DateTimeOffset>(10));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<bool> SetChallengeAsync(string tenantId, string agentSessionId,
        byte[] challenge, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        if (challenge.Length is < 16 or > 256) throw new ArgumentException("Challenge is invalid.");
        const string sql = """
            UPDATE certael_agent_sessions SET challenge=$3, challenge_expires_at=$4
            WHERE tenant_id=$1 AND agent_session_id=$2 AND revoked_at IS NULL
              AND expires_at > now() AND $4 <= now() + interval '2 minutes'
            """;
        return await ExecuteUpdate(tenantId, sql, cancellationToken,
            tenantId, agentSessionId, challenge, expiresAt);
    }

    public async ValueTask<bool> CommitReportAsync(string tenantId, AgentIntegrityReport report,
        byte[] canonicalReport, byte[] reportDigest, DateTimeOffset acceptedAt,
        CancellationToken cancellationToken)
    {
        if (canonicalReport.Length is < 1 or > AgentReportCodec.MaximumReport
            || reportDigest.Length != 32)
            throw new ArgumentException("Canonical Agent report is invalid.");
        const string advance = """
            UPDATE certael_agent_sessions
            SET last_sequence=$3, last_report_digest=$4, last_report_at=$5,
                challenge=NULL, challenge_expires_at=NULL
            WHERE tenant_id=$1 AND agent_session_id=$2 AND revoked_at IS NULL
              AND expires_at > $5 AND last_sequence=$3-1
              AND last_report_digest=$6 AND challenge=$7 AND challenge_expires_at > $5
            """;
        const string insert = """
            INSERT INTO certael_agent_reports(tenant_id, agent_session_id, sequence,
              report_digest, canonical_report, observed_at, accepted_at)
            VALUES($1,$2,$3,$4,$5,$6,$7)
            """;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using (var command = new NpgsqlCommand(advance, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(report.AgentSessionId);
            command.Parameters.AddWithValue((decimal)report.Sequence);
            command.Parameters.AddWithValue(reportDigest);
            command.Parameters.AddWithValue(acceptedAt);
            command.Parameters.AddWithValue(report.PreviousReportDigest);
            command.Parameters.AddWithValue(report.ChallengeNonce);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            { await transaction.RollbackAsync(cancellationToken); return false; }
        }
        await using (var command = new NpgsqlCommand(insert, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(report.AgentSessionId);
            command.Parameters.AddWithValue((decimal)report.Sequence);
            command.Parameters.AddWithValue(reportDigest);
            command.Parameters.AddWithValue(canonicalReport);
            command.Parameters.AddWithValue(DateTimeOffset.FromUnixTimeSeconds(report.ObservedAtUnix));
            command.Parameters.AddWithValue(acceptedAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async ValueTask<bool> RevokeAsync(string tenantId, string agentSessionId, string reason,
        DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 512 || reason.Any(char.IsControl))
            throw new ArgumentException("Revocation reason is invalid.");
        const string sql = """
            UPDATE certael_agent_sessions
            SET revoked_at=$3, revocation_reason=$4, challenge=NULL, challenge_expires_at=NULL
            WHERE tenant_id=$1 AND agent_session_id=$2 AND revoked_at IS NULL
            """;
        return await ExecuteUpdate(tenantId, sql, cancellationToken,
            tenantId, agentSessionId, revokedAt, reason);
    }

    private async ValueTask<bool> ExecuteUpdate(string tenantId, string sql,
        CancellationToken cancellationToken, params object[] values)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        bool updated = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
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
