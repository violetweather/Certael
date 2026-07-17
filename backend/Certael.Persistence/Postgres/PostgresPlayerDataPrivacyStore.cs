using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Certael.Server.Privacy;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresPlayerDataPrivacyStore(NpgsqlDataSource dataSource)
    : IPlayerDataPrivacyStore
{
    public async IAsyncEnumerable<string> ExportNdjsonAsync(string tenantId,
        string environmentId, string playerSubject,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        Validate(tenantId, environmentId, playerSubject);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            WITH player_cases AS (
                SELECT case_id FROM certael_cases
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
            )
            SELECT record::text FROM (
                SELECT created_at AS ordering, jsonb_build_object('kind','evidence','data',to_jsonb(e)) AS record
                FROM certael_evidence e
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
                UNION ALL
                SELECT created_at, jsonb_build_object('kind','verdict','data',to_jsonb(v))
                FROM certael_verdicts v
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
                UNION ALL
                SELECT observed_at, jsonb_build_object('kind','finding','data',to_jsonb(f))
                FROM certael_findings f
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
                UNION ALL
                SELECT created_at, jsonb_build_object('kind','case','data',to_jsonb(c))
                FROM certael_cases c
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
                UNION ALL
                SELECT n.created_at, jsonb_build_object('kind','case-note','data',to_jsonb(n))
                FROM certael_case_notes n WHERE n.tenant_id=$1 AND n.case_id IN (SELECT case_id FROM player_cases)
                UNION ALL
                SELECT a.occurred_at, jsonb_build_object('kind','case-activity','data',to_jsonb(a))
                FROM certael_case_activity a WHERE a.tenant_id=$1 AND a.case_id IN (SELECT case_id FROM player_cases)
                UNION ALL
                SELECT s.created_at, jsonb_build_object('kind','agent-session','data',to_jsonb(s))
                FROM certael_agent_sessions s
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
                UNION ALL
                SELECT s.created_at, jsonb_build_object('kind','core-session','data',to_jsonb(s))
                FROM certael_sessions s
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
                UNION ALL
                SELECT r.created_at, jsonb_build_object('kind','action-result','data',to_jsonb(r))
                FROM certael_action_results r
                JOIN certael_sessions s ON s.session_id=r.session_id
                WHERE s.tenant_id=$1 AND s.environment_id=$2 AND s.player_subject=$3
            ) records
            ORDER BY ordering
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(environmentId);
        command.Parameters.AddWithValue(playerSubject);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) yield return reader.GetString(0);
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<PlayerCaseRedactionResult> PseudonymizeCasesAsync(string tenantId,
        string environmentId, string playerSubject, CancellationToken cancellationToken)
    {
        Validate(tenantId, environmentId, playerSubject);
        string pseudonym = "deleted:" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{tenantId}\0{playerSubject}"))).ToLowerInvariant()[..32];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using (var privacy = new NpgsqlCommand(
            "SELECT set_config('certael.privacy_redaction', 'on', true)", connection, transaction))
            await privacy.ExecuteNonQueryAsync(cancellationToken);

        const string redactChildren = """
            WITH player_cases AS (
                SELECT case_id FROM certael_cases
                WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
            ), notes AS (
                UPDATE certael_case_notes SET body='[redacted by privacy deletion]'
                WHERE tenant_id=$1 AND case_id IN (SELECT case_id FROM player_cases)
            ), assignments AS (
                UPDATE certael_case_assignments SET reason='[redacted by privacy deletion]'
                WHERE tenant_id=$1 AND case_id IN (SELECT case_id FROM player_cases)
            ), dispositions AS (
                UPDATE certael_case_dispositions SET reason='[redacted by privacy deletion]'
                WHERE tenant_id=$1 AND case_id IN (SELECT case_id FROM player_cases)
            ), actions AS (
                UPDATE certael_bounded_actions
                SET target_id='[redacted]', reason='[redacted by privacy deletion]', public_result=NULL
                WHERE tenant_id=$1 AND case_id IN (SELECT case_id FROM player_cases)
            )
            UPDATE certael_case_activity
            SET reason='[redacted by privacy deletion]', details='{}'::jsonb
            WHERE tenant_id=$1 AND case_id IN (SELECT case_id FROM player_cases)
            """;
        await using (var children = new NpgsqlCommand(redactChildren, connection, transaction))
        {
            children.Parameters.AddWithValue(tenantId);
            children.Parameters.AddWithValue(environmentId);
            children.Parameters.AddWithValue(playerSubject);
            await children.ExecuteNonQueryAsync(cancellationToken);
        }
        const string redactCases = """
            UPDATE certael_cases
            SET player_subject=$4, title='Pseudonymized retained case',
                summary='Player-linked content removed by privacy deletion.',
                privacy_redacted_at=now(), updated_at=now(), version=version+1
            WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
            """;
        int cases;
        await using (var command = new NpgsqlCommand(redactCases, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            command.Parameters.AddWithValue(pseudonym);
            cases = await command.ExecuteNonQueryAsync(cancellationToken);
        }
        const string deleteOutbox = """
            DELETE FROM certael_outbox
            WHERE tenant_id=$1 AND environment_id=$2
              AND session_id IN (
                  SELECT session_id FROM certael_sessions
                  WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
              )
            """;
        await using (var command = new NpgsqlCommand(deleteOutbox, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        const string deleteSessions = """
            DELETE FROM certael_sessions
            WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3
            """;
        int coreSessions;
        await using (var command = new NpgsqlCommand(deleteSessions, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            coreSessions = await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new PlayerCaseRedactionResult(cases, coreSessions);
    }

    private static void Validate(string tenantId, string environmentId, string playerSubject)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(environmentId)
            || string.IsNullOrWhiteSpace(playerSubject) || tenantId.Length > 128
            || environmentId.Length > 128 || playerSubject.Length > 128)
            throw new ArgumentException("Tenant, environment, and player subject are invalid.");
    }

    private static async ValueTask SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
