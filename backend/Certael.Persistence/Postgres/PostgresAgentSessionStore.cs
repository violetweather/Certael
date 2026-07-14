using Certael.Server.Agent;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresAgentSessionStore : IAgentSessionStore
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeSpan _rawReportRetention;

    public PostgresAgentSessionStore(NpgsqlDataSource dataSource)
        : this(dataSource, TimeSpan.FromHours(24)) { }

    public PostgresAgentSessionStore(NpgsqlDataSource dataSource, TimeSpan rawReportRetention)
    {
        if (rawReportRetention < TimeSpan.FromMinutes(1)
            || rawReportRetention > TimeSpan.FromHours(24))
            throw new ArgumentOutOfRangeException(nameof(rawReportRetention));
        _dataSource = dataSource;
        _rawReportRetention = rawReportRetention;
    }

    public async ValueTask CreateAsync(VerifiedAgentSession session, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_agent_sessions(agent_session_id, tenant_id, game_id,
              environment_id, player_subject, match_id, build_id, agent_public_key,
              last_sequence, last_report_digest, expires_at, authoritative_server_id)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            """;
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
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
        command.Parameters.AddWithValue(session.AuthoritativeServerId);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<VerifiedAgentSession?> FindAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT agent_session_id, tenant_id, game_id, environment_id, player_subject,
              match_id, build_id, agent_public_key, last_sequence, last_report_digest, expires_at,
              authoritative_server_id
            FROM certael_agent_sessions
            WHERE tenant_id=$1 AND agent_session_id=$2 AND revoked_at IS NULL
            """;
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
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
            reader.GetFieldValue<byte[]>(9), reader.GetFieldValue<DateTimeOffset>(10), reader.GetString(11));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<AgentSessionAdmission?> FindAdmissionAsync(string tenantId,
        string agentSessionId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT agent_session_id, tenant_id, game_id, environment_id, player_subject,
              match_id, build_id, agent_public_key, last_sequence, last_report_digest, expires_at,
              authoritative_server_id, challenge, challenge_expires_at
            FROM certael_agent_sessions
            WHERE tenant_id=$1 AND agent_session_id=$2 AND revoked_at IS NULL
              AND challenge IS NOT NULL AND challenge_expires_at IS NOT NULL
            """;
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(agentSessionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var session = new VerifiedAgentSession(reader.GetString(0), reader.GetString(1),
            reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5),
            reader.GetString(6), reader.GetFieldValue<byte[]>(7), checked((ulong)reader.GetDecimal(8)),
            reader.GetFieldValue<byte[]>(9), reader.GetFieldValue<DateTimeOffset>(10), reader.GetString(11));
        var result = new AgentSessionAdmission(session, reader.GetFieldValue<byte[]>(12),
            reader.GetFieldValue<DateTimeOffset>(13));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<AgentStoredHealth?> HealthAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT agent_session_id, environment_id, authoritative_server_id, expires_at,
              last_report_at, revoked_at
            FROM certael_agent_sessions WHERE tenant_id=$1 AND agent_session_id=$2
            """;
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(agentSessionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var result = new AgentStoredHealth(reader.GetString(0), reader.GetString(1),
            reader.GetString(2), reader.GetFieldValue<DateTimeOffset>(3),
            reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4),
            reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5));
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
              report_digest, canonical_report, observed_at, accepted_at, expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            """;
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using (var purge = new NpgsqlCommand(
            "DELETE FROM certael_agent_reports WHERE tenant_id=$1 AND expires_at <= $2",
            connection, transaction))
        {
            purge.Parameters.AddWithValue(tenantId);
            purge.Parameters.AddWithValue(acceptedAt);
            await purge.ExecuteNonQueryAsync(cancellationToken);
        }
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
            command.Parameters.AddWithValue(acceptedAt.Add(_rawReportRetention));
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

    public async ValueTask<AgentPlayerDeletionResult> DeletePlayerAsync(string tenantId,
        string environmentId, string playerSubject, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(environmentId)
            || string.IsNullOrWhiteSpace(playerSubject) || tenantId.Length > 128
            || environmentId.Length > 128 || playerSubject.Length > 128)
            throw new ArgumentException("Tenant, environment, and player subject are invalid.");
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        const string deleteReports = """
            DELETE FROM certael_agent_reports reports
            USING certael_agent_sessions sessions
            WHERE reports.tenant_id=$1 AND sessions.tenant_id=$1
              AND reports.agent_session_id=sessions.agent_session_id
              AND sessions.environment_id=$2 AND sessions.player_subject=$3
            """;
        const string deleteSessions = """
            DELETE FROM certael_agent_sessions
            WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
            """;
        int reports;
        await using (var command = new NpgsqlCommand(deleteReports, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            reports = await command.ExecuteNonQueryAsync(cancellationToken);
        }
        int sessions;
        await using (var command = new NpgsqlCommand(deleteSessions, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            sessions = await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new AgentPlayerDeletionResult(sessions, reports);
    }

    private async ValueTask<bool> ExecuteUpdate(string tenantId, string sql,
        CancellationToken cancellationToken, params object[] values)
    {
        await using NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken);
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
