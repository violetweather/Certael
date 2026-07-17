using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certael.Server.Cases;
using Certael.Server.Evidence;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresCaseStore(
    NpgsqlDataSource dataSource,
    TimeSpan retention) : ICaseStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask<IReadOnlyList<CaseSummary>> SearchAsync(
        CaseQueueQuery query, CancellationToken cancellationToken)
    {
        if (query.Maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(query));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, query.TenantId, cancellationToken);
        const string sql = """
            SELECT case_id, tenant_id, game_id, environment_id, player_subject,
                   title, summary, state, signed_policy_id, signed_policy_version,
                   assigned_to, version, created_at, updated_at, resolved_at
            FROM certael_cases
            WHERE tenant_id = $1 AND environment_id = $2 AND expires_at > now()
              AND (($3::text IS NULL AND state IN ('Open', 'InReview')) OR state = $3)
              AND ($4::text IS NULL OR assigned_to = $4)
              AND ($5::text IS NULL OR player_subject = $5)
              AND ($6::text IS NULL OR title ILIKE '%' || $6 || '%'
                   OR summary ILIKE '%' || $6 || '%' OR player_subject ILIKE '%' || $6 || '%')
            ORDER BY updated_at DESC, case_id
            LIMIT $7
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(query.TenantId);
        command.Parameters.AddWithValue(query.EnvironmentId);
        AddNullableText(command, query.State?.ToString());
        AddNullableText(command, query.AssignedTo);
        AddNullableText(command, query.PlayerSubject);
        AddNullableText(command, string.IsNullOrWhiteSpace(query.Search) ? null : query.Search.Trim());
        command.Parameters.AddWithValue(query.Maximum);
        var results = new List<CaseSummary>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadSummary(reader));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return results;
    }

    public async ValueTask<CaseDetail?> FindAsync(
        string tenantId, Guid caseId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        CaseSummary? summary = await FindSummaryAsync(connection, transaction, tenantId, caseId,
            cancellationToken);
        if (summary is null) return null;

        IReadOnlyList<CaseEvidence> evidence = await ReadEvidenceAsync(
            connection, transaction, tenantId, caseId, cancellationToken);
        IReadOnlyList<CaseNote> notes = await ReadNotesAsync(
            connection, transaction, tenantId, caseId, cancellationToken);
        IReadOnlyList<CaseActivity> activity = await ReadActivityAsync(
            connection, transaction, tenantId, caseId, cancellationToken);
        IReadOnlyList<BoundedAction> actions = await ReadActionsAsync(
            connection, transaction, tenantId, caseId, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new CaseDetail(summary, evidence, notes, activity, actions);
    }

    public async ValueTask<CaseSummary?> OpenOrUpdateAsync(
        EvidenceBundle bundle, string title, string summary, string actorSubject,
        TimeSpan deduplicationWindow, CancellationToken cancellationToken)
    {
        ValidateNewCase(bundle, title, summary, actorSubject, deduplicationWindow);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        byte[] deduplicationKey = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|',
            bundle.Verdict.TenantId, bundle.Verdict.GameId, bundle.Verdict.EnvironmentId,
            bundle.Verdict.PlayerSubject, bundle.SignedPolicyId, bundle.SignedPolicyVersion)));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, bundle.Verdict.TenantId, cancellationToken);
        Guid caseId;
        bool created;
        const string existingSql = """
            SELECT case_id FROM certael_cases
            WHERE tenant_id = $1 AND deduplication_key = $2
              AND deduplication_until > $3 AND state IN ('Open', 'InReview')
            ORDER BY updated_at DESC LIMIT 1 FOR UPDATE
            """;
        await using (var existing = new NpgsqlCommand(existingSql, connection, transaction))
        {
            existing.Parameters.AddWithValue(bundle.Verdict.TenantId);
            existing.Parameters.AddWithValue(deduplicationKey);
            existing.Parameters.AddWithValue(now);
            object? value = await existing.ExecuteScalarAsync(cancellationToken);
            created = value is null;
            caseId = value is Guid id ? id : Guid.NewGuid();
        }

        if (created)
        {
            const string insert = """
                INSERT INTO certael_cases(tenant_id, case_id, game_id, environment_id,
                  player_subject, title, summary, state, signed_policy_id,
                  signed_policy_version, deduplication_key, deduplication_until, expires_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,'Open',$8,$9,$10,$11,$12)
                """;
            await using var command = new NpgsqlCommand(insert, connection, transaction);
            command.Parameters.AddWithValue(bundle.Verdict.TenantId);
            command.Parameters.AddWithValue(caseId);
            command.Parameters.AddWithValue(bundle.Verdict.GameId);
            command.Parameters.AddWithValue(bundle.Verdict.EnvironmentId);
            command.Parameters.AddWithValue(bundle.Verdict.PlayerSubject);
            command.Parameters.AddWithValue(title);
            command.Parameters.AddWithValue(summary);
            command.Parameters.AddWithValue(bundle.SignedPolicyId);
            command.Parameters.AddWithValue(bundle.SignedPolicyVersion);
            command.Parameters.AddWithValue(deduplicationKey);
            command.Parameters.AddWithValue(now + deduplicationWindow);
            command.Parameters.AddWithValue(now + ValidRetention());
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        else
        {
            await using var update = new NpgsqlCommand("""
                UPDATE certael_cases SET updated_at=$3, version=version+1,
                  deduplication_until=GREATEST(deduplication_until,$4)
                WHERE tenant_id=$1 AND case_id=$2
                """, connection, transaction);
            update.Parameters.AddWithValue(bundle.Verdict.TenantId);
            update.Parameters.AddWithValue(caseId);
            update.Parameters.AddWithValue(now);
            update.Parameters.AddWithValue(now + deduplicationWindow);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await AttachEvidenceAsync(connection, transaction, bundle, caseId, actorSubject,
            cancellationToken);
        await AppendActivityAsync(connection, transaction, bundle.Verdict.TenantId, caseId,
            actorSubject, created ? "CaseOpened" : "EvidenceAttached",
            created ? "Signed policy opened a case." : "Signed policy added evidence within the deduplication window.",
            new { bundle.Verdict.VerdictId, bundle.Verdict.Recommendation,
                bundle.SignedPolicyId, bundle.SignedPolicyVersion }, cancellationToken);
        CaseSummary? result = await FindSummaryAsync(connection, transaction,
            bundle.Verdict.TenantId, caseId, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<CaseSummary?> AssignAsync(
        string tenantId, Guid caseId, string? assignedTo, string actorSubject,
        string reason, long expectedVersion, CancellationToken cancellationToken)
    {
        ValidateMutation(actorSubject, reason, expectedVersion);
        return await MutateCaseAsync(tenantId, caseId, expectedVersion, actorSubject,
            "AssignmentChanged", reason, new { assignedTo }, async (connection, transaction) =>
            {
                await using var assignment = new NpgsqlCommand("""
                    INSERT INTO certael_case_assignments(tenant_id, assignment_id, case_id,
                      assigned_to, assigned_by, reason) VALUES ($1,$2,$3,$4,$5,$6)
                    """, connection, transaction);
                assignment.Parameters.AddWithValue(tenantId);
                assignment.Parameters.AddWithValue(Guid.NewGuid());
                assignment.Parameters.AddWithValue(caseId);
                AddNullableText(assignment, assignedTo);
                assignment.Parameters.AddWithValue(actorSubject);
                assignment.Parameters.AddWithValue(reason);
                await assignment.ExecuteNonQueryAsync(cancellationToken);
            }, "assigned_to=$4", command => AddNullableText(command, assignedTo), cancellationToken);
    }

    public async ValueTask<CaseNote?> AddNoteAsync(
        string tenantId, Guid caseId, string authorSubject, string body,
        long expectedVersion, CancellationToken cancellationToken)
    {
        ValidateMutation(authorSubject, body, expectedVersion, 4096);
        Guid noteId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        if (!await TouchCaseAsync(connection, transaction, tenantId, caseId, expectedVersion,
            cancellationToken)) return null;
        await using (var note = new NpgsqlCommand("""
            INSERT INTO certael_case_notes(tenant_id,note_id,case_id,author_subject,body,created_at)
            VALUES ($1,$2,$3,$4,$5,$6)
            """, connection, transaction))
        {
            note.Parameters.AddWithValue(tenantId); note.Parameters.AddWithValue(noteId);
            note.Parameters.AddWithValue(caseId); note.Parameters.AddWithValue(authorSubject);
            note.Parameters.AddWithValue(body); note.Parameters.AddWithValue(now);
            await note.ExecuteNonQueryAsync(cancellationToken);
        }
        await AppendActivityAsync(connection, transaction, tenantId, caseId, authorSubject,
            "NoteAdded", "Operator added an internal note.", new { noteId }, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new CaseNote(noteId, authorSubject, body, now);
    }

    public async ValueTask<CaseSummary?> TransitionAsync(
        string tenantId, Guid caseId, CaseState targetState,
        CaseDisposition? disposition, string actorSubject, string reason,
        long expectedVersion, CancellationToken cancellationToken)
    {
        ValidateMutation(actorSubject, reason, expectedVersion, 2048);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        CaseSummary? current = await FindSummaryAsync(connection, transaction, tenantId, caseId,
            cancellationToken, true);
        if (current is null || current.Version != expectedVersion
            || !ValidTransition(current.State, targetState)
            || ((targetState is CaseState.Resolved or CaseState.Dismissed) && disposition is null))
            return null;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using (var update = new NpgsqlCommand("""
            UPDATE certael_cases SET state=$3, version=version+1, updated_at=$4,
              resolved_at=CASE WHEN $3 IN ('Resolved','Dismissed') THEN $4 ELSE NULL END
            WHERE tenant_id=$1 AND case_id=$2 AND version=$5
            """, connection, transaction))
        {
            update.Parameters.AddWithValue(tenantId); update.Parameters.AddWithValue(caseId);
            update.Parameters.AddWithValue(targetState.ToString()); update.Parameters.AddWithValue(now);
            update.Parameters.AddWithValue(expectedVersion);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) return null;
        }
        if (disposition is not null)
        {
            await using var record = new NpgsqlCommand("""
                INSERT INTO certael_case_dispositions(tenant_id,disposition_id,case_id,
                  disposition,reason,actor_subject) VALUES ($1,$2,$3,$4,$5,$6)
                """, connection, transaction);
            record.Parameters.AddWithValue(tenantId); record.Parameters.AddWithValue(Guid.NewGuid());
            record.Parameters.AddWithValue(caseId); record.Parameters.AddWithValue(disposition.ToString()!);
            record.Parameters.AddWithValue(reason); record.Parameters.AddWithValue(actorSubject);
            await record.ExecuteNonQueryAsync(cancellationToken);
        }
        await AppendActivityAsync(connection, transaction, tenantId, caseId, actorSubject,
            targetState == CaseState.Open ? "CaseReopened" : "StateChanged", reason,
            new { from = current.State, to = targetState, disposition }, cancellationToken);
        CaseSummary? result = await FindSummaryAsync(connection, transaction, tenantId, caseId,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<BoundedAction?> ApproveActionAsync(
        string tenantId, Guid caseId, BoundedActionKind kind,
        string targetType, string targetId, string reason,
        string requestedBy, string approvedBy, byte[] authorizationDigest,
        long expectedVersion, CancellationToken cancellationToken)
    {
        ValidateMutation(approvedBy, reason, expectedVersion, 2048);
        if (string.IsNullOrWhiteSpace(requestedBy) || string.IsNullOrWhiteSpace(targetType)
            || string.IsNullOrWhiteSpace(targetId) || authorizationDigest.Length != 32)
            throw new ArgumentException("Bounded action input is invalid.");
        Guid actionId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        CaseSummary? current = await FindSummaryAsync(connection, transaction, tenantId, caseId,
            cancellationToken, true);
        if (current is null || current.Version != expectedVersion || current.State != CaseState.InReview)
            return null;
        if (!await TouchCaseAsync(connection, transaction, tenantId, caseId, expectedVersion,
            cancellationToken)) return null;
        await using (var command = new NpgsqlCommand("""
            INSERT INTO certael_bounded_actions(tenant_id,bounded_action_id,case_id,action_kind,
              target_type,target_id,reason,requested_by,approved_by,authorization_digest,
              status,requested_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'Approved',$11)
            """, connection, transaction))
        {
            command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(actionId);
            command.Parameters.AddWithValue(caseId); command.Parameters.AddWithValue(kind.ToString());
            command.Parameters.AddWithValue(targetType); command.Parameters.AddWithValue(targetId);
            command.Parameters.AddWithValue(reason); command.Parameters.AddWithValue(requestedBy);
            command.Parameters.AddWithValue(approvedBy); command.Parameters.AddWithValue(authorizationDigest);
            command.Parameters.AddWithValue(now);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await AppendActivityAsync(connection, transaction, tenantId, caseId, approvedBy,
            "BoundedActionApproved", reason,
            new { boundedActionId = actionId, kind, targetType, targetId, requestedBy, approvedBy },
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new BoundedAction(actionId, kind, targetType, targetId, reason, requestedBy,
            approvedBy, "Approved", null, now, null);
    }

    private async Task<CaseSummary?> MutateCaseAsync(string tenantId, Guid caseId,
        long expectedVersion, string actorSubject, string activityType, string reason,
        object details, Func<NpgsqlConnection, NpgsqlTransaction, Task> appendRecord,
        string additionalSet, Action<NpgsqlCommand> addParameter,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using (var update = new NpgsqlCommand($"""
            UPDATE certael_cases SET version=version+1, updated_at=now(), {additionalSet}
            WHERE tenant_id=$1 AND case_id=$2 AND version=$3
            """, connection, transaction))
        {
            update.Parameters.AddWithValue(tenantId); update.Parameters.AddWithValue(caseId);
            update.Parameters.AddWithValue(expectedVersion); addParameter(update);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) return null;
        }
        await appendRecord(connection, transaction);
        await AppendActivityAsync(connection, transaction, tenantId, caseId, actorSubject,
            activityType, reason, details, cancellationToken);
        CaseSummary? result = await FindSummaryAsync(connection, transaction, tenantId, caseId,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static async Task<bool> TouchCaseAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, Guid caseId, long expectedVersion,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            UPDATE certael_cases SET version=version+1, updated_at=now()
            WHERE tenant_id=$1 AND case_id=$2 AND version=$3
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(caseId);
        command.Parameters.AddWithValue(expectedVersion);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static async Task AttachEvidenceAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, EvidenceBundle bundle, Guid caseId, string actorSubject,
        CancellationToken cancellationToken)
    {
        foreach (Guid? findingId in bundle.Findings.Select(value => (Guid?)value.FindingId).Prepend(null))
        {
            await using var command = new NpgsqlCommand("""
                INSERT INTO certael_case_evidence(tenant_id,case_evidence_id,case_id,
                  verdict_id,finding_id,attached_by) VALUES ($1,$2,$3,$4,$5,$6)
                ON CONFLICT DO NOTHING
                """, connection, transaction);
            command.Parameters.AddWithValue(bundle.Verdict.TenantId);
            command.Parameters.AddWithValue(Guid.NewGuid()); command.Parameters.AddWithValue(caseId);
            command.Parameters.AddWithValue(bundle.Verdict.VerdictId);
            command.Parameters.AddWithValue((object?)findingId ?? DBNull.Value);
            command.Parameters.AddWithValue(actorSubject);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async Task AppendActivityAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, Guid caseId, string actorSubject,
        string activityType, string reason, object details, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_case_activity(tenant_id,activity_id,case_id,actor_subject,
              activity_type,reason,details) VALUES ($1,$2,$3,$4,$5,$6,$7)
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(Guid.NewGuid());
        command.Parameters.AddWithValue(caseId); command.Parameters.AddWithValue(actorSubject);
        command.Parameters.AddWithValue(activityType); command.Parameters.AddWithValue(reason);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(details, Json));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<CaseSummary?> FindSummaryAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, Guid caseId,
        CancellationToken cancellationToken, bool forUpdate = false)
    {
        string sql = """
            SELECT case_id, tenant_id, game_id, environment_id, player_subject,
                   title, summary, state, signed_policy_id, signed_policy_version,
                   assigned_to, version, created_at, updated_at, resolved_at
            FROM certael_cases WHERE tenant_id=$1 AND case_id=$2 AND expires_at > now()
            """ + (forUpdate ? " FOR UPDATE" : string.Empty);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(caseId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSummary(reader) : null;
    }

    private static CaseSummary ReadSummary(NpgsqlDataReader reader) => new(
        reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        reader.GetString(4), reader.GetString(5), reader.GetString(6),
        Enum.Parse<CaseState>(reader.GetString(7)), reader.GetString(8), reader.GetString(9),
        reader.IsDBNull(10) ? null : reader.GetString(10), reader.GetInt64(11),
        reader.GetFieldValue<DateTimeOffset>(12), reader.GetFieldValue<DateTimeOffset>(13),
        reader.IsDBNull(14) ? null : reader.GetFieldValue<DateTimeOffset>(14));

    private static async Task<IReadOnlyList<CaseEvidence>> ReadEvidenceAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string tenantId,
        Guid caseId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT ce.verdict_id, ce.finding_id, COALESCE(f.rule_id,''),
              COALESCE(f.rule_version,''), f.signal_family, f.trust, f.risk_contribution,
              f.confidence, COALESCE(f.observed_at,v.created_at), v.replay_digest,
              COALESCE(f.fields,'[]'::jsonb)::text
            FROM certael_case_evidence ce
            JOIN certael_verdicts v ON v.tenant_id=ce.tenant_id AND v.verdict_id=ce.verdict_id
            LEFT JOIN certael_findings f ON f.tenant_id=ce.tenant_id AND f.finding_id=ce.finding_id
            WHERE ce.tenant_id=$1 AND ce.case_id=$2
            ORDER BY COALESCE(f.observed_at,v.created_at), ce.case_evidence_id
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(caseId);
        var values = new List<CaseEvidence>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            values.Add(new CaseEvidence(reader.GetGuid(0), reader.IsDBNull(1) ? null : reader.GetGuid(1),
                reader.GetString(2), reader.GetString(3), ParseNullable<SignalFamily>(reader, 4),
                ParseNullable<FindingTrust>(reader, 5), reader.IsDBNull(6) ? null : reader.GetInt32(6),
                reader.IsDBNull(7) ? null : reader.GetDouble(7), reader.GetFieldValue<DateTimeOffset>(8),
                reader.GetFieldValue<byte[]>(9), reader.GetString(10)));
        return values;
    }

    private static async Task<IReadOnlyList<CaseNote>> ReadNotesAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string tenantId,
        Guid caseId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT note_id,author_subject,body,created_at FROM certael_case_notes
            WHERE tenant_id=$1 AND case_id=$2 ORDER BY created_at,note_id
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(caseId);
        var values = new List<CaseNote>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) values.Add(new CaseNote(
            reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
            reader.GetFieldValue<DateTimeOffset>(3)));
        return values;
    }

    private static async Task<IReadOnlyList<CaseActivity>> ReadActivityAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string tenantId,
        Guid caseId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT activity_id,actor_subject,activity_type,reason,details::text,occurred_at
            FROM certael_case_activity WHERE tenant_id=$1 AND case_id=$2
            ORDER BY occurred_at,activity_id
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(caseId);
        var values = new List<CaseActivity>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) values.Add(new CaseActivity(
            reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
            reader.GetString(4), reader.GetFieldValue<DateTimeOffset>(5)));
        return values;
    }

    private static async Task<IReadOnlyList<BoundedAction>> ReadActionsAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string tenantId,
        Guid caseId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT bounded_action_id,action_kind,target_type,target_id,reason,requested_by,
              approved_by,status,public_result,requested_at,completed_at
            FROM certael_bounded_actions WHERE tenant_id=$1 AND case_id=$2
            ORDER BY requested_at,bounded_action_id
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(caseId);
        var values = new List<BoundedAction>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) values.Add(new BoundedAction(
            reader.GetGuid(0), Enum.Parse<BoundedActionKind>(reader.GetString(1)),
            reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5),
            reader.GetString(6), reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8),
            reader.GetFieldValue<DateTimeOffset>(9), reader.IsDBNull(10) ? null :
                reader.GetFieldValue<DateTimeOffset>(10)));
        return values;
    }

    private TimeSpan ValidRetention()
    {
        if (retention <= TimeSpan.Zero || retention > TimeSpan.FromDays(180))
            throw new InvalidOperationException("Case retention must be between one tick and 180 days.");
        return retention;
    }

    private static void ValidateNewCase(EvidenceBundle bundle, string title, string summary,
        string actorSubject, TimeSpan deduplicationWindow)
    {
        bool review = bundle.Verdict.Recommendation is VerdictRecommendation.RestrictSession
            or VerdictRecommendation.RecommendKick
            or VerdictRecommendation.RecommendTemporarySuspension
            or VerdictRecommendation.RecommendManualReview;
        if (!review || bundle.SignedPolicyId == "legacy" || string.IsNullOrWhiteSpace(bundle.SignedPolicyId)
            || string.IsNullOrWhiteSpace(bundle.SignedPolicyVersion) || title.Length is < 1 or > 256
            || summary.Length is < 1 or > 4096 || string.IsNullOrWhiteSpace(actorSubject)
            || deduplicationWindow <= TimeSpan.Zero || deduplicationWindow > TimeSpan.FromHours(24))
            throw new ArgumentException("Signed policy case input is invalid.");
    }

    private static void ValidateMutation(string actorSubject, string reason,
        long expectedVersion, int maximumReason = 512)
    {
        if (string.IsNullOrWhiteSpace(actorSubject) || string.IsNullOrWhiteSpace(reason)
            || reason.Length > maximumReason || expectedVersion < 1 || reason.Any(char.IsControl))
            throw new ArgumentException("Case mutation input is invalid.");
    }

    private static bool ValidTransition(CaseState current, CaseState target) =>
        (current, target) switch
        {
            (CaseState.Open, CaseState.InReview) => true,
            (CaseState.InReview, CaseState.Resolved or CaseState.Dismissed) => true,
            (CaseState.Resolved or CaseState.Dismissed, CaseState.Open) => true,
            _ => false
        };

    private static T? ParseNullable<T>(NpgsqlDataReader reader, int ordinal) where T : struct, Enum =>
        reader.IsDBNull(ordinal) ? null : Enum.Parse<T>(reader.GetString(ordinal));

    private static void AddNullableText(NpgsqlCommand command, string? value) =>
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Text,
            Value = value is null ? DBNull.Value : value });

    private static async Task SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
