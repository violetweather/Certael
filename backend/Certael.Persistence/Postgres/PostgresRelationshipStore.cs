using System.Security.Cryptography;
using System.Text.Json;
using Certael.Server.Economy;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed record RelationshipProfileSummary(string TenantId, string ProfileId,
    string Version, string GameId, string EnvironmentId, EconomyProfileStage Stage,
    int CanaryPercentage, string KeyId, byte[] Digest, DateTimeOffset CreatedAt);

public sealed record PersistedRelationshipFinding(string ProfileId, string ProfileVersion,
    EconomyProfileStage ProfileStage, RelationshipFinding Finding);

public sealed class PostgresRelationshipStore(NpgsqlDataSource dataSource,
    TimeSpan? retention = null)
{
    private readonly TimeSpan _retention = retention ?? TimeSpan.FromDays(90);

    public async ValueTask ProjectAsync(RelationshipEventV1 value,
        CancellationToken cancellationToken)
    {
        if (_retention <= TimeSpan.Zero || _retention > TimeSpan.FromDays(90))
            throw new InvalidOperationException(
                "Relationship retention must be between one tick and 90 days.");
        byte[] payload = RelationshipEventV1Codec.Encode(value);
        byte[] digest = SHA256.HashData(payload);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, value.TenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_relationship_edges(tenant_id,game_id,environment_id,event_id,
              edge_kind,source_subject,target_subject,weight,occurred_at,authoritative_action_id,
              canonical_payload,replay_digest,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ON CONFLICT DO NOTHING
            """, connection, transaction);
        command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.GameId);
        command.Parameters.AddWithValue(value.EnvironmentId); command.Parameters.AddWithValue(value.EventId);
        command.Parameters.AddWithValue(value.Kind.ToString()); command.Parameters.AddWithValue(value.SourceSubject);
        command.Parameters.AddWithValue(value.TargetSubject); command.Parameters.AddWithValue(value.Weight);
        command.Parameters.AddWithValue(value.OccurredAt); command.Parameters.AddWithValue(value.AuthoritativeActionId);
        command.Parameters.AddWithValue(payload); command.Parameters.AddWithValue(digest);
        command.Parameters.AddWithValue(value.OccurredAt + _retention);
        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            await using var existing = new NpgsqlCommand("""
                SELECT canonical_payload FROM certael_relationship_edges
                WHERE tenant_id=$1 AND event_id=$2
                """, connection, transaction);
            existing.Parameters.AddWithValue(value.TenantId); existing.Parameters.AddWithValue(value.EventId);
            object? found = await existing.ExecuteScalarAsync(cancellationToken);
            if (found is not byte[] canonical
                || !CryptographicOperations.FixedTimeEquals(canonical, payload))
                throw new EconomyEventException(
                    "Relationship event ID is already bound to different content.");
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<IReadOnlyList<RelationshipEventV1>> LoadWindowAsync(
        string tenantId, string gameId, string environmentId,
        DateTimeOffset startExclusive, DateTimeOffset endInclusive, int maximumEvents,
        CancellationToken cancellationToken)
    {
        if (maximumEvents is < 1 or > 100_000 || startExclusive >= endInclusive)
            throw new ArgumentOutOfRangeException(nameof(maximumEvents));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT canonical_payload FROM certael_relationship_edges
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
              AND occurred_at>$4 AND occurred_at<=$5 AND canonical_payload IS NOT NULL
            ORDER BY occurred_at,event_id LIMIT $6
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId); command.Parameters.AddWithValue(startExclusive);
        command.Parameters.AddWithValue(endInclusive); command.Parameters.AddWithValue(maximumEvents + 1);
        var events = new List<RelationshipEventV1>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (events.Count == maximumEvents)
                throw new EconomyEventException("Relationship analysis window exceeds its event limit.");
            events.Add(RelationshipEventV1Codec.Decode(reader.GetFieldValue<byte[]>(0)));
        }
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return events;
    }

    public async ValueTask SaveFindingsAsync(string tenantId, string gameId,
        string environmentId, IEnumerable<PersistedRelationshipFinding> findings,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        foreach (PersistedRelationshipFinding persisted in findings)
        {
            RelationshipFinding finding = persisted.Finding;
            byte[] context = System.Text.Encoding.UTF8.GetBytes(
                $"{persisted.ProfileId}\0{persisted.ProfileVersion}\0{persisted.ProfileStage}\0{finding.RuleId}\0{finding.WindowDays}");
            byte[] identity = SHA256.HashData(finding.ReplayDigest.Concat(context).ToArray());
            Guid findingId = new(identity.AsSpan(0, 16), bigEndian: true);
            await using var command = new NpgsqlCommand("""
                INSERT INTO certael_relationship_findings(tenant_id,finding_id,game_id,
                  environment_id,profile_id,profile_version,profile_stage,rule_id,rule_version,
                  window_days,event_ids,baseline_version,threshold,replay_digest,expires_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                ON CONFLICT (tenant_id,finding_id) DO NOTHING
                """, connection, transaction);
            command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(findingId);
            command.Parameters.AddWithValue(gameId); command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(persisted.ProfileId);
            command.Parameters.AddWithValue(persisted.ProfileVersion);
            command.Parameters.AddWithValue(persisted.ProfileStage.ToString());
            command.Parameters.AddWithValue(finding.RuleId); command.Parameters.AddWithValue(finding.RuleVersion);
            command.Parameters.AddWithValue(finding.WindowDays);
            command.Parameters.AddWithValue(finding.ExactEdges.Select(edge => edge.EventId).ToArray());
            command.Parameters.AddWithValue(finding.BaselineVersion);
            command.Parameters.AddWithValue(finding.Threshold); command.Parameters.AddWithValue(finding.ReplayDigest);
            command.Parameters.AddWithValue(finding.ExactEdges.Max(edge => edge.OccurredAt) + _retention);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<IReadOnlyList<RelationshipProfileDeployment>> LoadActiveProfilesAsync(
        string tenantId, string gameId, string environmentId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT canonical_profile,signature,key_id,digest,stage,canary_percentage
            FROM certael_relationship_profiles
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
              AND stage IN ('Shadow','Canary','Enforced')
            ORDER BY created_at,profile_id,version
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId);
        var results = new List<RelationshipProfileDeployment>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            results.Add(new RelationshipProfileDeployment(
                new SignedRelationshipProtectionProfile(reader.GetFieldValue<byte[]>(0),
                    reader.GetFieldValue<byte[]>(1), reader.GetString(2),
                    reader.GetFieldValue<byte[]>(3)),
                Enum.Parse<EconomyProfileStage>(reader.GetString(4)), reader.GetInt32(5)));
        await reader.DisposeAsync(); await transaction.CommitAsync(cancellationToken);
        return results;
    }

    public async ValueTask<RelationshipProfileSummary> AddProfileAsync(
        SignedRelationshipProtectionProfile signed, RelationshipProtectionProfile profile,
        string actorSubject, CancellationToken cancellationToken)
    {
        ValidateActor(actorSubject);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(signed.CanonicalProfile), signed.Digest)
            || !CryptographicOperations.FixedTimeEquals(
                RelationshipProtectionProfileSigner.EncodeCanonical(profile), signed.CanonicalProfile))
            throw new EconomyEventException("Relationship profile digest is invalid.");
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, profile.TenantId, cancellationToken);
        await using (var command = new NpgsqlCommand("""
            INSERT INTO certael_relationship_profiles(tenant_id,profile_id,version,game_id,
              environment_id,stage,canary_percentage,canonical_profile,signature,key_id,digest)
            VALUES($1,$2,$3,$4,$5,'Shadow',0,$6,$7,$8,$9)
            ON CONFLICT (tenant_id,profile_id,version) DO NOTHING
            """, connection, transaction))
        {
            command.Parameters.AddWithValue(profile.TenantId); command.Parameters.AddWithValue(profile.ProfileId);
            command.Parameters.AddWithValue(profile.Version); command.Parameters.AddWithValue(profile.GameId);
            command.Parameters.AddWithValue(profile.EnvironmentId); command.Parameters.AddWithValue(signed.CanonicalProfile);
            command.Parameters.AddWithValue(signed.Signature); command.Parameters.AddWithValue(signed.KeyId);
            command.Parameters.AddWithValue(signed.Digest);
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            {
                RelationshipProfileSummary existing = await FindProfileAsync(connection, transaction,
                    profile.TenantId, profile.ProfileId, profile.Version, cancellationToken)
                    ?? throw new EconomyEventException("Relationship profile conflict could not be read.");
                if (!CryptographicOperations.FixedTimeEquals(existing.Digest, signed.Digest))
                    throw new EconomyEventException(
                        "Relationship profile version is already bound to another digest.");
                await transaction.CommitAsync(cancellationToken); return existing;
            }
        }
        await AppendActivityAsync(connection, transaction, profile.TenantId, profile.ProfileId,
            profile.Version, "ProfileAdded", actorSubject,
            new { stage = EconomyProfileStage.Shadow.ToString(), digest = Convert.ToHexString(signed.Digest) },
            cancellationToken);
        RelationshipProfileSummary result = await FindProfileAsync(connection, transaction,
            profile.TenantId, profile.ProfileId, profile.Version, cancellationToken)
            ?? throw new EconomyEventException("Relationship profile was not persisted.");
        await transaction.CommitAsync(cancellationToken); return result;
    }

    public async ValueTask<RelationshipProfileSummary?> DeployProfileAsync(string tenantId,
        string gameId, string environmentId, string profileId, string version,
        EconomyProfileStage expectedStage, EconomyProfileStage targetStage,
        int canaryPercentage, string actorSubject, CancellationToken cancellationToken)
    {
        EconomyProfileDeploymentValidation.Validate(targetStage, canaryPercentage);
        ValidateActor(actorSubject);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.Serializable, cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        RelationshipProfileSummary? current = await FindProfileAsync(connection, transaction,
            tenantId, profileId, version, cancellationToken, true);
        if (current is null || current.GameId != gameId || current.EnvironmentId != environmentId
            || current.Stage != expectedStage || !ValidTransition(current.Stage, targetStage))
        { await transaction.RollbackAsync(cancellationToken); return null; }
        if (targetStage == EconomyProfileStage.Enforced)
        {
            await using var supersede = new NpgsqlCommand("""
                UPDATE certael_relationship_profiles SET stage='RolledBack',canary_percentage=0
                WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND stage='Enforced'
                  AND NOT (profile_id=$4 AND version=$5)
                RETURNING profile_id,version
                """, connection, transaction);
            supersede.Parameters.AddWithValue(tenantId); supersede.Parameters.AddWithValue(gameId);
            supersede.Parameters.AddWithValue(environmentId); supersede.Parameters.AddWithValue(profileId);
            supersede.Parameters.AddWithValue(version);
            var superseded = new List<(string ProfileId, string Version)>();
            await using (NpgsqlDataReader reader = await supersede.ExecuteReaderAsync(cancellationToken))
                while (await reader.ReadAsync(cancellationToken))
                    superseded.Add((reader.GetString(0), reader.GetString(1)));
            foreach ((string supersededId, string supersededVersion) in superseded)
                await AppendActivityAsync(connection, transaction, tenantId, supersededId,
                    supersededVersion, "ProfileSuperseded", actorSubject,
                    new { replacementProfileId = profileId, replacementVersion = version },
                    cancellationToken);
        }
        await using (var update = new NpgsqlCommand("""
            UPDATE certael_relationship_profiles SET stage=$4,canary_percentage=$5
            WHERE tenant_id=$1 AND profile_id=$2 AND version=$3 AND stage=$6
            """, connection, transaction))
        {
            update.Parameters.AddWithValue(tenantId); update.Parameters.AddWithValue(profileId);
            update.Parameters.AddWithValue(version); update.Parameters.AddWithValue(targetStage.ToString());
            update.Parameters.AddWithValue(canaryPercentage); update.Parameters.AddWithValue(expectedStage.ToString());
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        await AppendActivityAsync(connection, transaction, tenantId, profileId, version,
            targetStage == EconomyProfileStage.RolledBack ? "ProfileRolledBack" : "ProfilePromoted",
            actorSubject, new { from = expectedStage.ToString(), to = targetStage.ToString(), canaryPercentage },
            cancellationToken);
        RelationshipProfileSummary result = await FindProfileAsync(connection, transaction,
            tenantId, profileId, version, cancellationToken)
            ?? throw new EconomyEventException("Relationship profile deployment disappeared.");
        await transaction.CommitAsync(cancellationToken); return result;
    }

    public async ValueTask<IReadOnlyList<RelationshipProfileSummary>> ListProfilesAsync(
        string tenantId, string gameId, string environmentId,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT tenant_id,profile_id,version,game_id,environment_id,stage,
              canary_percentage,key_id,digest,created_at
            FROM certael_relationship_profiles
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
            ORDER BY created_at DESC,profile_id,version LIMIT 1000
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId);
        var results = new List<RelationshipProfileSummary>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadProfile(reader));
        await reader.DisposeAsync(); await transaction.CommitAsync(cancellationToken); return results;
    }

    private static bool ValidTransition(EconomyProfileStage from, EconomyProfileStage to) =>
        from != to && (from, to) switch
        {
            (EconomyProfileStage.Shadow, EconomyProfileStage.Canary or EconomyProfileStage.Enforced
                or EconomyProfileStage.RolledBack) => true,
            (EconomyProfileStage.Canary, EconomyProfileStage.Shadow or EconomyProfileStage.Enforced
                or EconomyProfileStage.RolledBack) => true,
            (EconomyProfileStage.Enforced, EconomyProfileStage.RolledBack) => true,
            (EconomyProfileStage.RolledBack, EconomyProfileStage.Shadow) => true,
            _ => false
        };

    private static async ValueTask<RelationshipProfileSummary?> FindProfileAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string tenantId,
        string profileId, string version, CancellationToken cancellationToken,
        bool forUpdate = false)
    {
        string sql = """
            SELECT tenant_id,profile_id,version,game_id,environment_id,stage,
              canary_percentage,key_id,digest,created_at
            FROM certael_relationship_profiles
            WHERE tenant_id=$1 AND profile_id=$2 AND version=$3
            """ + (forUpdate ? " FOR UPDATE" : "");
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(profileId);
        command.Parameters.AddWithValue(version);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadProfile(reader) : null;
    }

    private static RelationshipProfileSummary ReadProfile(NpgsqlDataReader reader) => new(
        reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        reader.GetString(4), Enum.Parse<EconomyProfileStage>(reader.GetString(5)),
        reader.GetInt32(6), reader.GetString(7), reader.GetFieldValue<byte[]>(8),
        reader.GetFieldValue<DateTimeOffset>(9));

    private static async ValueTask AppendActivityAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, string profileId, string version,
        string activity, string actor, object details, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_relationship_profile_activity(tenant_id,activity_id,profile_id,
              version,activity,actor_subject,details) VALUES($1,$2,$3,$4,$5,$6,$7)
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(Guid.NewGuid());
        command.Parameters.AddWithValue(profileId); command.Parameters.AddWithValue(version);
        command.Parameters.AddWithValue(activity); command.Parameters.AddWithValue(actor);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(details));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void ValidateActor(string actor)
    {
        if (actor.Length is < 1 or > 128 || actor.Any(char.IsControl))
            throw new EconomyEventException("Relationship profile actor is invalid.");
    }

    private static async ValueTask SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id',$1,true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
