using System.Security.Cryptography;
using System.Text.Json;
using Certael.Server.Economy;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed record EconomyProfileSummary(string TenantId, string ProfileId, string Version,
    string GameId, string EnvironmentId, EconomyProfileStage Stage, int CanaryPercentage,
    string KeyId, byte[] Digest, DateTimeOffset CreatedAt);

public sealed class PostgresEconomyStore(NpgsqlDataSource dataSource, TimeSpan? retention = null)
{
    private readonly TimeSpan _retention = retention ?? TimeSpan.FromDays(90);

    public async ValueTask ProjectAsync(EconomyEventV1 value, CancellationToken cancellationToken)
    {
        if (_retention <= TimeSpan.Zero || _retention > TimeSpan.FromDays(90))
            throw new InvalidOperationException("Economy retention must be between one tick and 90 days.");
        byte[] payload = EconomyEventV1Codec.Encode(value);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, value.TenantId, cancellationToken);
        const string insertEvent = """
            INSERT INTO certael_economy_events(tenant_id,event_id,game_id,environment_id,player_subject,
              event_kind,authoritative_action_id,transaction_id,mutation_id,reason_code,canonical_payload,
              replay_digest,occurred_at,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            ON CONFLICT (tenant_id,event_id) DO NOTHING
            """;
        await using (var command = new NpgsqlCommand(insertEvent, connection, transaction))
        {
            command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.EventId);
            command.Parameters.AddWithValue(value.GameId); command.Parameters.AddWithValue(value.EnvironmentId);
            command.Parameters.AddWithValue(value.PlayerSubject); command.Parameters.AddWithValue(value.Kind.ToString());
            command.Parameters.AddWithValue(value.Transaction?.AuthoritativeActionId ?? value.ItemMutation!.AuthoritativeActionId);
            command.Parameters.Add(new NpgsqlParameter { Value = (object?)value.Transaction?.TransactionId ?? DBNull.Value });
            command.Parameters.Add(new NpgsqlParameter { Value = (object?)value.ItemMutation?.MutationId ?? DBNull.Value });
            command.Parameters.AddWithValue(value.Transaction?.ReasonCode ?? value.ItemMutation!.ReasonCode);
            command.Parameters.AddWithValue(payload);
            command.Parameters.AddWithValue(EconomyEventV1Codec.ReplayDigest([value]));
            command.Parameters.AddWithValue(value.OccurredAt); command.Parameters.AddWithValue(value.OccurredAt + _retention);
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            { await transaction.CommitAsync(cancellationToken); return; }
        }
        if (value.Transaction is not null)
        {
            const string insertLine = """
                INSERT INTO certael_economy_ledger_lines(tenant_id,event_id,line_number,account_id,asset_id,quantity,occurred_at)
                VALUES($1,$2,$3,$4,$5,$6,$7)
                """;
            for (int index = 0; index < value.Transaction.Lines.Count; index++)
            {
                EconomyLedgerLine line = value.Transaction.Lines[index];
                await using var command = new NpgsqlCommand(insertLine, connection, transaction);
                command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.EventId);
                command.Parameters.AddWithValue(index); command.Parameters.AddWithValue(line.AccountId);
                command.Parameters.AddWithValue(line.AssetId); command.Parameters.AddWithValue(line.Quantity);
                command.Parameters.AddWithValue(value.OccurredAt); await command.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        else
        {
            ItemLineageMutation item = value.ItemMutation!;
            const string insertItem = """
                INSERT INTO certael_item_lineage(tenant_id,event_id,item_id,parent_item_id,asset_id,account_id,mutation_kind,occurred_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                """;
            await using var command = new NpgsqlCommand(insertItem, connection, transaction);
            command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.EventId);
            command.Parameters.AddWithValue(item.ItemId);
            command.Parameters.Add(new NpgsqlParameter { Value = (object?)item.ParentItemId ?? DBNull.Value });
            command.Parameters.AddWithValue(item.AssetId); command.Parameters.AddWithValue(item.AccountId);
            command.Parameters.AddWithValue(item.MutationKind.ToString()); command.Parameters.AddWithValue(value.OccurredAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask SaveFindingsAsync(string tenantId, string gameId, string environmentId,
        IEnumerable<EconomyFinding> findings, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            INSERT INTO certael_economy_findings(tenant_id,finding_id,game_id,environment_id,rule_id,
              rule_version,profile_id,profile_version,profile_stage,event_ids,authoritative_fields,
              window_start,window_end,replay_digest,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            ON CONFLICT (tenant_id,finding_id) DO NOTHING
            """;
        foreach (EconomyFinding finding in findings)
        {
            byte[] identityContext = System.Text.Encoding.UTF8.GetBytes(
                $"{finding.RuleId}\0{finding.ProfileId}\0{finding.ProfileVersion}\0{finding.ProfileStage}");
            byte[] identity = SHA256.HashData(finding.ReplayDigest.Concat(identityContext).ToArray());
            Guid findingId = new(identity.AsSpan(0, 16));
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(findingId);
            command.Parameters.AddWithValue(gameId); command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(finding.RuleId); command.Parameters.AddWithValue(finding.RuleVersion);
            command.Parameters.AddWithValue(finding.ProfileId);
            command.Parameters.AddWithValue(finding.ProfileVersion);
            command.Parameters.AddWithValue(finding.ProfileStage.ToString());
            command.Parameters.AddWithValue(finding.EventIds.ToArray());
            command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(finding.AuthoritativeFields));
            command.Parameters.AddWithValue(finding.WindowStart); command.Parameters.AddWithValue(finding.WindowEnd);
            command.Parameters.AddWithValue(finding.ReplayDigest); command.Parameters.AddWithValue(finding.WindowEnd + _retention);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask<IReadOnlyList<EconomyEventV1>> LoadPlayerWindowAsync(
        string tenantId, string gameId, string environmentId, string playerSubject,
        DateTimeOffset startExclusive, DateTimeOffset endInclusive, int maximumEvents,
        CancellationToken cancellationToken)
    {
        if (maximumEvents is < 1 or > 100_000 || startExclusive >= endInclusive)
            throw new ArgumentOutOfRangeException(nameof(maximumEvents));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            SELECT canonical_payload
            FROM certael_economy_events
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND player_subject=$4
              AND occurred_at>$5 AND occurred_at<=$6
            ORDER BY occurred_at,event_id
            LIMIT $7
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId); command.Parameters.AddWithValue(playerSubject);
        command.Parameters.AddWithValue(startExclusive); command.Parameters.AddWithValue(endInclusive);
        command.Parameters.AddWithValue(maximumEvents + 1);
        var events = new List<EconomyEventV1>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (events.Count == maximumEvents)
                throw new EconomyEventException("Economy analysis window exceeds its event limit.");
            events.Add(EconomyEventV1Codec.Decode(reader.GetFieldValue<byte[]>(0)));
        }
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return events;
    }

    public async ValueTask<IReadOnlyList<EconomyProfileDeployment>> LoadActiveProfilesAsync(
        string tenantId, string gameId, string environmentId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            SELECT canonical_profile,signature,key_id,digest,stage,canary_percentage
            FROM certael_economy_profiles
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
              AND stage IN ('Shadow','Canary','Enforced')
            ORDER BY created_at,profile_id,version
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId);
        var profiles = new List<EconomyProfileDeployment>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            profiles.Add(new EconomyProfileDeployment(new SignedEconomyProtectionProfile(
                reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
                reader.GetString(2), reader.GetFieldValue<byte[]>(3)),
                Enum.Parse<EconomyProfileStage>(reader.GetString(4)), reader.GetInt32(5)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return profiles;
    }

    public async ValueTask<EconomyProfileSummary> AddProfileAsync(
        SignedEconomyProtectionProfile signed, EconomyProtectionProfile profile,
        string actorSubject, CancellationToken cancellationToken)
    {
        if (actorSubject.Length is < 1 or > 128 || actorSubject.Any(char.IsControl))
            throw new EconomyEventException("Economy profile actor is invalid.");
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(signed.CanonicalProfile),
                signed.Digest)
            || !CryptographicOperations.FixedTimeEquals(
                EconomyProtectionProfileSigner.EncodeCanonical(profile), signed.CanonicalProfile))
            throw new EconomyEventException("Economy profile digest is invalid.");
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, profile.TenantId, cancellationToken);
        const string sql = """
            INSERT INTO certael_economy_profiles(tenant_id,profile_id,version,game_id,
              environment_id,stage,canary_percentage,canonical_profile,signature,key_id,digest)
            VALUES($1,$2,$3,$4,$5,'Shadow',0,$6,$7,$8,$9)
            ON CONFLICT (tenant_id,profile_id,version) DO NOTHING
            """;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        {
            command.Parameters.AddWithValue(profile.TenantId); command.Parameters.AddWithValue(profile.ProfileId);
            command.Parameters.AddWithValue(profile.Version); command.Parameters.AddWithValue(profile.GameId);
            command.Parameters.AddWithValue(profile.EnvironmentId);
            command.Parameters.AddWithValue(signed.CanonicalProfile); command.Parameters.AddWithValue(signed.Signature);
            command.Parameters.AddWithValue(signed.KeyId); command.Parameters.AddWithValue(signed.Digest);
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            {
                EconomyProfileSummary existing = await FindProfileAsync(connection, transaction,
                    profile.TenantId, profile.ProfileId, profile.Version, cancellationToken)
                    ?? throw new EconomyEventException("Economy profile conflict could not be read.");
                if (!CryptographicOperations.FixedTimeEquals(existing.Digest, signed.Digest))
                    throw new EconomyEventException(
                        "Economy profile version is already bound to another digest.");
                await transaction.CommitAsync(cancellationToken);
                return existing;
            }
        }
        await AppendProfileActivityAsync(connection, transaction, profile.TenantId,
            profile.ProfileId, profile.Version, "ProfileAdded", actorSubject,
            new { stage = EconomyProfileStage.Shadow.ToString(), digest = Convert.ToHexString(signed.Digest) },
            cancellationToken);
        EconomyProfileSummary result = await FindProfileAsync(connection, transaction,
            profile.TenantId, profile.ProfileId, profile.Version, cancellationToken)
            ?? throw new EconomyEventException("Economy profile was not persisted.");
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<EconomyProfileSummary?> DeployProfileAsync(string tenantId,
        string gameId, string environmentId, string profileId, string version,
        EconomyProfileStage expectedStage,
        EconomyProfileStage targetStage, int canaryPercentage, string actorSubject,
        CancellationToken cancellationToken)
    {
        EconomyProfileDeploymentValidation.Validate(targetStage, canaryPercentage);
        if (actorSubject.Length is < 1 or > 128 || actorSubject.Any(char.IsControl))
            throw new EconomyEventException("Economy profile actor is invalid.");
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.Serializable, cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        EconomyProfileSummary? current = await FindProfileAsync(connection, transaction,
            tenantId, profileId, version, cancellationToken, forUpdate: true);
        if (current is null || current.GameId != gameId || current.EnvironmentId != environmentId
            || current.Stage != expectedStage
            || !ValidProfileTransition(current.Stage, targetStage))
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        if (targetStage == EconomyProfileStage.Enforced)
        {
            await using var supersede = new NpgsqlCommand("""
                UPDATE certael_economy_profiles SET stage='RolledBack',canary_percentage=0
                WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND stage='Enforced'
                  AND NOT (profile_id=$4 AND version=$5)
                RETURNING profile_id,version
                """, connection, transaction);
            supersede.Parameters.AddWithValue(tenantId); supersede.Parameters.AddWithValue(current.GameId);
            supersede.Parameters.AddWithValue(current.EnvironmentId); supersede.Parameters.AddWithValue(profileId);
            supersede.Parameters.AddWithValue(version);
            var superseded = new List<(string ProfileId, string Version)>();
            await using (NpgsqlDataReader reader = await supersede.ExecuteReaderAsync(cancellationToken))
                while (await reader.ReadAsync(cancellationToken))
                    superseded.Add((reader.GetString(0), reader.GetString(1)));
            foreach ((string supersededId, string supersededVersion) in superseded)
                await AppendProfileActivityAsync(connection, transaction, tenantId, supersededId,
                    supersededVersion, "ProfileSuperseded", actorSubject,
                    new { replacementProfileId = profileId, replacementVersion = version },
                    cancellationToken);
        }
        await using (var update = new NpgsqlCommand("""
            UPDATE certael_economy_profiles SET stage=$4,canary_percentage=$5
            WHERE tenant_id=$1 AND profile_id=$2 AND version=$3 AND stage=$6
            """, connection, transaction))
        {
            update.Parameters.AddWithValue(tenantId); update.Parameters.AddWithValue(profileId);
            update.Parameters.AddWithValue(version); update.Parameters.AddWithValue(targetStage.ToString());
            update.Parameters.AddWithValue(canaryPercentage); update.Parameters.AddWithValue(expectedStage.ToString());
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        await AppendProfileActivityAsync(connection, transaction, tenantId, profileId, version,
            targetStage == EconomyProfileStage.RolledBack ? "ProfileRolledBack" : "ProfilePromoted",
            actorSubject, new { from = expectedStage.ToString(), to = targetStage.ToString(), canaryPercentage },
            cancellationToken);
        EconomyProfileSummary result = await FindProfileAsync(connection, transaction,
            tenantId, profileId, version, cancellationToken)
            ?? throw new EconomyEventException("Economy profile deployment disappeared.");
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    public async ValueTask<IReadOnlyList<EconomyProfileSummary>> ListProfilesAsync(string tenantId,
        string gameId, string environmentId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT tenant_id,profile_id,version,game_id,environment_id,stage,
              canary_percentage,key_id,digest,created_at
            FROM certael_economy_profiles
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
            ORDER BY created_at DESC,profile_id,version
            LIMIT 1000
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(gameId);
        command.Parameters.AddWithValue(environmentId);
        var results = new List<EconomyProfileSummary>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadProfile(reader));
        await reader.DisposeAsync(); await transaction.CommitAsync(cancellationToken);
        return results;
    }

    private static bool ValidProfileTransition(EconomyProfileStage from, EconomyProfileStage to) =>
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

    private static async ValueTask<EconomyProfileSummary?> FindProfileAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string tenantId,
        string profileId, string version, CancellationToken cancellationToken,
        bool forUpdate = false)
    {
        string sql = """
            SELECT tenant_id,profile_id,version,game_id,environment_id,stage,
              canary_percentage,key_id,digest,created_at
            FROM certael_economy_profiles
            WHERE tenant_id=$1 AND profile_id=$2 AND version=$3
            """ + (forUpdate ? " FOR UPDATE" : "");
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(profileId);
        command.Parameters.AddWithValue(version);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadProfile(reader) : null;
    }

    private static EconomyProfileSummary ReadProfile(NpgsqlDataReader reader) => new(
        reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        reader.GetString(4), Enum.Parse<EconomyProfileStage>(reader.GetString(5)), reader.GetInt32(6),
        reader.GetString(7), reader.GetFieldValue<byte[]>(8), reader.GetFieldValue<DateTimeOffset>(9));

    private static async ValueTask AppendProfileActivityAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, string profileId, string version,
        string activity, string actor, object details, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_economy_profile_activity(tenant_id,activity_id,profile_id,
              version,activity,actor_subject,details)
            VALUES($1,$2,$3,$4,$5,$6,$7)
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(Guid.NewGuid());
        command.Parameters.AddWithValue(profileId); command.Parameters.AddWithValue(version);
        command.Parameters.AddWithValue(activity); command.Parameters.AddWithValue(actor);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(details));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask SetTenantAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id',$1,true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId); await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
