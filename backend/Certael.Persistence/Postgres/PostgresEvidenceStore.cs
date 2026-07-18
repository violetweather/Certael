using System.Text.Json;
using Certael.Server.Evidence;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresEvidenceStore(
    NpgsqlDataSource dataSource,
    TimeSpan retention) : IEvidenceStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask SaveAsync(EvidenceBundle bundle, CancellationToken cancellationToken)
    {
        if (retention <= TimeSpan.Zero || retention > TimeSpan.FromDays(3660))
            throw new InvalidOperationException("Evidence retention is invalid.");
        if (bundle.Findings.Any(value => value.TenantId != bundle.Verdict.TenantId))
            throw new InvalidOperationException("Cross-tenant evidence is prohibited.");
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, bundle.Verdict.TenantId, cancellationToken);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using (var purge = new NpgsqlCommand(
            "DELETE FROM certael_evidence WHERE tenant_id=$1 AND expires_at <= $2",
            connection, transaction))
        {
            purge.Parameters.AddWithValue(bundle.Verdict.TenantId);
            purge.Parameters.AddWithValue(now);
            await purge.ExecuteNonQueryAsync(cancellationToken);
        }
        const string sql = """
            INSERT INTO certael_evidence(tenant_id, verdict_id, game_id, environment_id,
              player_subject, bundle, replay_digest, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (tenant_id,verdict_id) DO NOTHING
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(bundle.Verdict.TenantId); command.Parameters.AddWithValue(bundle.Verdict.VerdictId);
        command.Parameters.AddWithValue(bundle.Verdict.GameId); command.Parameters.AddWithValue(bundle.Verdict.EnvironmentId);
        command.Parameters.AddWithValue(bundle.Verdict.PlayerSubject);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(bundle, Json));
        command.Parameters.AddWithValue(bundle.ReplayDigest);
        DateTimeOffset expiresAt = now + RetentionFor(bundle, retention);
        command.Parameters.AddWithValue(expiresAt);
        int inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        if (inserted == 0)
        {
            await using var existing = new NpgsqlCommand(
                "SELECT replay_digest FROM certael_evidence WHERE tenant_id=$1 AND verdict_id=$2",
                connection, transaction);
            existing.Parameters.AddWithValue(bundle.Verdict.TenantId);
            existing.Parameters.AddWithValue(bundle.Verdict.VerdictId);
            object? stored = await existing.ExecuteScalarAsync(cancellationToken);
            if (stored is not byte[] digest
                || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    digest, bundle.ReplayDigest))
                throw new InvalidOperationException(
                    "Evidence verdict ID is already bound to a different replay digest.");
            await transaction.CommitAsync(cancellationToken);
            return;
        }
        await SaveNormalizedAsync(connection, transaction, bundle, expiresAt, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public static TimeSpan RetentionFor(EvidenceBundle bundle, TimeSpan configured)
    {
        if (configured <= TimeSpan.Zero || configured > TimeSpan.FromDays(3660))
            throw new InvalidOperationException("Evidence retention is invalid.");
        bool containsAdvisory = bundle.Findings.Any(finding =>
            finding.Trust != FindingTrust.Authoritative);
        return containsAdvisory && configured > TimeSpan.FromDays(30)
            ? TimeSpan.FromDays(30) : configured;
    }

    public async ValueTask<EvidenceSearchPage> SearchAsync(
        EvidenceSearchQuery query, CancellationToken cancellationToken)
    {
        if (query.PageSize is < 1 or > 250) throw new ArgumentOutOfRangeException(nameof(query));
        EvidenceSearchCursor? cursor = query.Cursor is null
            ? null : EvidenceSearchCursorCodec.Decode(query.Cursor);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, query.TenantId, cancellationToken);
        string sortExpression = query.SortBy switch
        {
            EvidenceSortField.Risk => "lpad(v.risk_score::text,10,'0')",
            EvidenceSortField.Confidence => "to_char(v.confidence,'FM0.000000000')",
            EvidenceSortField.Player => "v.player_subject",
            EvidenceSortField.Rule => "COALESCE(stats.first_rule,'')",
            EvidenceSortField.Signal => "COALESCE(stats.first_signal,'')",
            _ => "to_char(v.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US')"
        };
        string comparison = query.SortDirection == EvidenceSortDirection.Descending ? "<" : ">";
        string direction = query.SortDirection == EvidenceSortDirection.Descending ? "DESC" : "ASC";
        string sql = $"""
            WITH candidates AS (
              SELECT v.verdict_id, v.tenant_id, v.game_id, v.environment_id, v.session_id,
                     v.player_subject, v.risk_score, v.confidence, v.recommendation,
                     COALESCE(stats.rule_ids, ARRAY[]::text[]) AS rule_ids,
                     COALESCE(stats.signal_families, ARRAY[]::text[]) AS signal_families,
                     COALESCE(stats.finding_count, 0)::int AS finding_count,
                     v.created_at, {sortExpression} AS sort_key
              FROM certael_verdicts v
              LEFT JOIN LATERAL (
                SELECT array_agg(DISTINCT f.rule_id ORDER BY f.rule_id) AS rule_ids,
                       array_agg(DISTINCT f.signal_family ORDER BY f.signal_family) AS signal_families,
                       min(f.rule_id) AS first_rule,
                       min(f.signal_family) AS first_signal,
                       count(*) AS finding_count
                FROM certael_verdict_findings vf
                JOIN certael_findings f ON f.tenant_id=vf.tenant_id AND f.finding_id=vf.finding_id
                WHERE vf.tenant_id=v.tenant_id AND vf.verdict_id=v.verdict_id
                  AND f.expires_at > now()
              ) stats ON true
              WHERE v.tenant_id=$1 AND v.environment_id=$2 AND v.expires_at > now()
                AND ($3::text IS NULL OR v.player_subject=$3)
                AND ($4::text IS NULL OR v.session_id=$4)
                AND ($5::text IS NULL OR EXISTS (
                    SELECT 1 FROM certael_verdict_findings vf
                    JOIN certael_findings f ON f.tenant_id=vf.tenant_id AND f.finding_id=vf.finding_id
                    WHERE vf.tenant_id=v.tenant_id AND vf.verdict_id=v.verdict_id
                      AND f.rule_id ILIKE '%' || $5 || '%'))
                AND ($6::text IS NULL OR $6=ANY(stats.signal_families))
                AND ($7::text IS NULL OR v.recommendation=$7)
                AND ($8::text IS NULL OR v.player_subject ILIKE '%' || $8 || '%'
                    OR v.session_id ILIKE '%' || $8 || '%'
                    OR v.verdict_id::text ILIKE '%' || $8 || '%'
                    OR v.recommendation ILIKE '%' || $8 || '%'
                    OR EXISTS (SELECT 1 FROM certael_verdict_findings vf
                      JOIN certael_findings f ON f.tenant_id=vf.tenant_id AND f.finding_id=vf.finding_id
                      WHERE vf.tenant_id=v.tenant_id AND vf.verdict_id=v.verdict_id
                        AND (f.rule_id ILIKE '%' || $8 || '%'
                          OR f.rule_version ILIKE '%' || $8 || '%'
                          OR f.signal_family ILIKE '%' || $8 || '%')))
            )
            SELECT * FROM candidates
            WHERE ($9::text IS NULL OR sort_key {comparison} $9
                OR (sort_key=$9 AND verdict_id {comparison} $10))
            ORDER BY sort_key {direction}, verdict_id {direction}
            LIMIT $11
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(query.TenantId);
        command.Parameters.AddWithValue(query.EnvironmentId);
        AddNullableText(command, query.PlayerSubject);
        AddNullableText(command, query.SessionId);
        AddNullableText(command, query.RuleId);
        AddNullableText(command, query.SignalFamily?.ToString());
        AddNullableText(command, query.Recommendation?.ToString());
        AddNullableText(command, string.IsNullOrWhiteSpace(query.Search) ? null : query.Search.Trim());
        AddNullableText(command, cursor?.SortValue);
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Uuid,
            Value = cursor is null ? DBNull.Value : cursor.VerdictId });
        command.Parameters.AddWithValue(query.PageSize + 1);
        var results = new List<(EvidenceSummary Summary, string SortKey)>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add((new EvidenceSummary(reader.GetGuid(0), reader.GetString(1),
                reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5),
                reader.GetInt32(6), reader.GetDouble(7),
                Enum.Parse<VerdictRecommendation>(reader.GetString(8)),
                reader.GetFieldValue<string[]>(9), reader.GetFieldValue<string[]>(10)
                    .Select(Enum.Parse<SignalFamily>).ToArray(), reader.GetInt32(11),
                reader.GetFieldValue<DateTimeOffset>(12)), reader.GetString(13)));
        }
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        bool hasMore = results.Count > query.PageSize;
        (EvidenceSummary Summary, string SortKey)[] returned = results.Take(query.PageSize).ToArray();
        string? next = hasMore && returned.Length > 0
            ? EvidenceSearchCursorCodec.Encode(new EvidenceSearchCursor(
                returned[^1].SortKey, returned[^1].Summary.VerdictId)) : null;
        return new EvidenceSearchPage(returned.Select(value => value.Summary).ToArray(), next, hasMore);
    }

    public async ValueTask<EvidenceBundle?> FindAsync(string tenantId, Guid verdictId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT bundle FROM certael_evidence WHERE tenant_id=$1 AND verdict_id=$2 AND expires_at > now()",
            connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(verdictId);
        object? value = await command.ExecuteScalarAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return value is string json ? JsonSerializer.Deserialize<EvidenceBundle>(json, Json) : null;
    }

    public async ValueTask DeletePlayerAsync(string tenantId, string environmentId,
        string playerSubject, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenant(connection, transaction, tenantId, cancellationToken);
        string[] statements =
        [
            "DELETE FROM certael_evidence WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3",
            "DELETE FROM certael_verdicts WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3",
            "DELETE FROM certael_findings WHERE tenant_id=$1 AND environment_id=$2 AND player_subject=$3",
        ];
        foreach (string sql in statements)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            command.Parameters.AddWithValue(tenantId);
            command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(playerSubject);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task SetTenant(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddNullableText(NpgsqlCommand command, string? value) =>
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Text,
            Value = value is null ? DBNull.Value : value });

    private static async Task SaveNormalizedAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, EvidenceBundle bundle, DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        const string verdictSql = """
            INSERT INTO certael_verdicts(tenant_id, verdict_id, game_id, environment_id,
              session_id, player_subject, risk_score, confidence, recommendation,
              rule_versions, replay_digest, bundle, created_at, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            """;
        await using (var verdict = new NpgsqlCommand(verdictSql, connection, transaction))
        {
            verdict.Parameters.AddWithValue(bundle.Verdict.TenantId);
            verdict.Parameters.AddWithValue(bundle.Verdict.VerdictId);
            verdict.Parameters.AddWithValue(bundle.Verdict.GameId);
            verdict.Parameters.AddWithValue(bundle.Verdict.EnvironmentId);
            verdict.Parameters.AddWithValue(bundle.Verdict.SessionId);
            verdict.Parameters.AddWithValue(bundle.Verdict.PlayerSubject);
            verdict.Parameters.AddWithValue(bundle.Verdict.RiskScore);
            verdict.Parameters.AddWithValue(bundle.Verdict.Confidence);
            verdict.Parameters.AddWithValue(bundle.Verdict.Recommendation.ToString());
            verdict.Parameters.AddWithValue(bundle.Verdict.RuleVersions.ToArray());
            verdict.Parameters.AddWithValue(bundle.ReplayDigest);
            verdict.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(bundle, Json));
            verdict.Parameters.AddWithValue(bundle.Verdict.CreatedAt);
            verdict.Parameters.AddWithValue(expiresAt);
            await verdict.ExecuteNonQueryAsync(cancellationToken);
        }

        const string findingSql = """
            INSERT INTO certael_findings(tenant_id, finding_id, game_id, environment_id,
              session_id, player_subject, rule_id, rule_version, rule_pack_digest,
              action_id, signal_family, trust, risk_contribution, confidence, fields,
              observed_at, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
            """;
        const string linkSql = """
            INSERT INTO certael_verdict_findings(tenant_id, verdict_id, finding_id)
            VALUES ($1,$2,$3)
            """;
        foreach (Finding findingValue in bundle.Findings)
        {
            await using (var finding = new NpgsqlCommand(findingSql, connection, transaction))
            {
                finding.Parameters.AddWithValue(findingValue.TenantId);
                finding.Parameters.AddWithValue(findingValue.FindingId);
                finding.Parameters.AddWithValue(findingValue.GameId);
                finding.Parameters.AddWithValue(findingValue.EnvironmentId);
                finding.Parameters.AddWithValue(findingValue.SessionId);
                finding.Parameters.AddWithValue(findingValue.PlayerSubject);
                finding.Parameters.AddWithValue(findingValue.RuleId);
                finding.Parameters.AddWithValue(findingValue.RuleVersion);
                finding.Parameters.AddWithValue(findingValue.RulePackDigest);
                finding.Parameters.AddWithValue((object?)findingValue.ActionId ?? DBNull.Value);
                finding.Parameters.AddWithValue(findingValue.SignalFamily.ToString());
                finding.Parameters.AddWithValue(findingValue.Trust.ToString());
                finding.Parameters.AddWithValue(findingValue.RiskContribution);
                finding.Parameters.AddWithValue(findingValue.Confidence);
                finding.Parameters.AddWithValue(NpgsqlDbType.Jsonb,
                    JsonSerializer.Serialize(findingValue.Fields, Json));
                finding.Parameters.AddWithValue(findingValue.ObservedAt);
                finding.Parameters.AddWithValue(expiresAt);
                await finding.ExecuteNonQueryAsync(cancellationToken);
            }
            await using var link = new NpgsqlCommand(linkSql, connection, transaction);
            link.Parameters.AddWithValue(bundle.Verdict.TenantId);
            link.Parameters.AddWithValue(bundle.Verdict.VerdictId);
            link.Parameters.AddWithValue(findingValue.FindingId);
            await link.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
