using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Certael.Server.Sessions;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Coordinator;

public sealed class CoordinatorStore(NpgsqlDataSource dataSource)
{
    public async ValueTask<RegionalLeaseV1?> AcquireAsync(string tenant, string game,
        string environment, string match, string region, string server, bool force,
        string actor, CancellationToken cancellationToken)
    {
        ValidateIdentifiers(tenant, game, environment, match, region, server, actor);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        DateTimeOffset now = await DatabaseNow(connection, transaction, cancellationToken);
        const string select = """
            SELECT owner_region, owner_server, fencing_epoch, expires_at, released_at
            FROM certael_match_leases
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
            FOR UPDATE
            """;
        await using var query = new NpgsqlCommand(select, connection, transaction);
        AddKey(query, tenant, game, environment, match);
        string? oldRegion = null, oldServer = null; long epoch = 0;
        DateTimeOffset expires = DateTimeOffset.MinValue; bool released = false;
        await using (NpgsqlDataReader reader = await query.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                oldRegion = reader.GetString(0); oldServer = reader.GetString(1);
                epoch = reader.GetInt64(2); expires = reader.GetFieldValue<DateTimeOffset>(3);
                released = !reader.IsDBNull(4);
            }
        }
        bool active = oldRegion is not null && !released && expires > now;
        if (active && !force)
        {
            if (oldRegion == region && oldServer == server)
            {
                await transaction.CommitAsync(cancellationToken);
                return new(tenant, game, environment, match, region, server, epoch, expires);
            }
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        long next = checked(epoch + 1); DateTimeOffset nextExpiry = now.AddSeconds(30);
        const string upsert = """
            INSERT INTO certael_match_leases
                (tenant_id, game_id, environment_id, match_id, owner_region, owner_server,
                 fencing_epoch, expires_at, released_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL)
            ON CONFLICT (tenant_id,game_id,environment_id,match_id) DO UPDATE SET
                owner_region=$5, owner_server=$6, fencing_epoch=$7, expires_at=$8,
                released_at=NULL
            """;
        await using (var command = new NpgsqlCommand(upsert, connection, transaction))
        {
            AddKey(command, tenant, game, environment, match);
            command.Parameters.AddWithValue(region); command.Parameters.AddWithValue(server);
            command.Parameters.AddWithValue(next); command.Parameters.AddWithValue(nextExpiry);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await Audit(connection, transaction, tenant, game, environment, match,
            force ? "ForcedFailover" : "LeaseAcquired", actor, next,
            new { oldRegion, oldServer, region, server, previousEpoch = epoch }, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(tenant, game, environment, match, region, server, next, nextExpiry);
    }

    public async ValueTask<RegionalLeaseV1?> RenewAsync(RegionalLeaseV1 lease,
        CancellationToken cancellationToken)
    {
        ValidateLease(lease);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        const string sql = """
            UPDATE certael_match_leases SET expires_at=now()+interval '30 seconds'
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
              AND owner_region=$5 AND owner_server=$6 AND fencing_epoch=$7
              AND released_at IS NULL AND expires_at>now()
            RETURNING expires_at
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        AddLease(command, lease);
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return result is DateTimeOffset expires ? lease with { ExpiresAt = expires } : null;
    }

    public async ValueTask<bool> ReleaseAsync(RegionalLeaseV1 lease, string actor,
        CancellationToken cancellationToken)
    {
        ValidateLease(lease); ValidateIdentifiers(actor);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        const string sql = """
            UPDATE certael_match_leases SET released_at=now()
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
              AND owner_region=$5 AND owner_server=$6 AND fencing_epoch=$7
              AND released_at IS NULL
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        AddLease(command, lease);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        { await transaction.RollbackAsync(cancellationToken); return false; }
        await Audit(connection, transaction, lease.TenantId, lease.GameId,
            lease.EnvironmentId, lease.MatchId, "LeaseReleased", actor,
            lease.FencingEpoch, new { lease.OwnerRegion, lease.OwnerServer }, cancellationToken);
        await transaction.CommitAsync(cancellationToken); return true;
    }

    public async ValueTask<bool> IsCurrentOwnerAsync(RegionalLeaseV1 lease,
        CancellationToken cancellationToken)
    {
        ValidateLease(lease);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        const string sql = """
            SELECT 1 FROM certael_match_leases
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
              AND owner_region=$5 AND owner_server=$6 AND fencing_epoch=$7
              AND released_at IS NULL AND expires_at>now()
            """;
        await using var command = new NpgsqlCommand(sql, connection); AddLease(command, lease);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    public async ValueTask<bool> RecordGrantIfOwnerAsync(RegionalLeaseV1 lease,
        RegionTransferGrantV1 grant, SignedRegionTransferGrant signed, string actor,
        CancellationToken cancellationToken)
    {
        ValidateLease(lease); ValidateIdentifiers(actor);
        if (grant.TenantId != lease.TenantId || grant.GameId != lease.GameId
            || grant.EnvironmentId != lease.EnvironmentId || grant.MatchId != lease.MatchId
            || grant.SourceRegion != lease.OwnerRegion || grant.LeaseEpoch != lease.FencingEpoch
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(signed.CanonicalGrant), signed.Digest)) return false;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        const string owner = """
            SELECT 1 FROM certael_match_leases
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
              AND owner_region=$5 AND owner_server=$6 AND fencing_epoch=$7
              AND released_at IS NULL AND expires_at>now() FOR UPDATE
            """;
        await using (var check = new NpgsqlCommand(owner, connection, transaction))
        {
            AddLease(check, lease);
            if (await check.ExecuteScalarAsync(cancellationToken) is null)
            { await transaction.RollbackAsync(cancellationToken); return false; }
        }
        const string insert = """
            INSERT INTO certael_region_transfer_grants
                (grant_id,tenant_id,game_id,environment_id,match_id,player_subject,
                 source_region,destination_region,fencing_epoch,nonce_digest,
                 canonical_digest,issued_at,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            """;
        await using (var command = new NpgsqlCommand(insert, connection, transaction))
        {
            command.Parameters.AddWithValue(grant.GrantId); AddKey(command, grant.TenantId,
                grant.GameId, grant.EnvironmentId, grant.MatchId);
            command.Parameters.AddWithValue(grant.PlayerSubject);
            command.Parameters.AddWithValue(grant.SourceRegion);
            command.Parameters.AddWithValue(grant.DestinationRegion);
            command.Parameters.AddWithValue(grant.LeaseEpoch);
            command.Parameters.AddWithValue(SHA256.HashData(grant.Nonce));
            command.Parameters.AddWithValue(signed.Digest);
            command.Parameters.AddWithValue(grant.IssuedAt);
            command.Parameters.AddWithValue(grant.ExpiresAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await Audit(connection, transaction, grant.TenantId, grant.GameId, grant.EnvironmentId,
            grant.MatchId, "TransferGrantIssued", actor, grant.LeaseEpoch,
            new { grant.GrantId, grant.PlayerSubject, grant.SourceRegion,
                grant.DestinationRegion }, cancellationToken);
        await transaction.CommitAsync(cancellationToken); return true;
    }

    public async ValueTask<RegionalLeaseV1?> RedeemAsync(RegionTransferGrantV1 grant,
        SignedRegionTransferGrant signed, string destinationServer, string actor,
        CancellationToken cancellationToken)
    {
        ValidateIdentifiers(destinationServer, actor);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        DateTimeOffset now = await DatabaseNow(connection, transaction, cancellationToken);
        const string selectGrant = """
            SELECT tenant_id,game_id,environment_id,match_id,player_subject,source_region,
                   destination_region,fencing_epoch,nonce_digest,canonical_digest,
                   issued_at,expires_at,redeemed_at
            FROM certael_region_transfer_grants WHERE grant_id=$1 FOR UPDATE
            """;
        await using (var command = new NpgsqlCommand(selectGrant, connection, transaction))
        {
            command.Parameters.AddWithValue(grant.GrantId);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || !StoredGrantMatches(reader, grant, signed) || !reader.IsDBNull(12)
                || reader.GetFieldValue<DateTimeOffset>(11) <= now)
            { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        const string selectLease = """
            SELECT owner_region,fencing_epoch,expires_at,released_at
            FROM certael_match_leases
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
            FOR UPDATE
            """;
        await using (var command = new NpgsqlCommand(selectLease, connection, transaction))
        {
            AddKey(command, grant.TenantId, grant.GameId, grant.EnvironmentId, grant.MatchId);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || reader.GetString(0) != grant.SourceRegion
                || reader.GetInt64(1) != grant.LeaseEpoch
                || reader.IsDBNull(3) && reader.GetFieldValue<DateTimeOffset>(2) > now)
            { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        long nextEpoch = checked(grant.LeaseEpoch + 1);
        DateTimeOffset nextExpiry = now.AddSeconds(30);
        const string transferOwnership = """
            UPDATE certael_match_leases SET owner_region=$5,owner_server=$6,
                fencing_epoch=$7,expires_at=$8,released_at=NULL
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3 AND match_id=$4
              AND fencing_epoch=$9
            """;
        await using (var command = new NpgsqlCommand(transferOwnership, connection, transaction))
        {
            AddKey(command, grant.TenantId, grant.GameId, grant.EnvironmentId, grant.MatchId);
            command.Parameters.AddWithValue(grant.DestinationRegion);
            command.Parameters.AddWithValue(destinationServer); command.Parameters.AddWithValue(nextEpoch);
            command.Parameters.AddWithValue(nextExpiry); command.Parameters.AddWithValue(grant.LeaseEpoch);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        const string redeem = """
            UPDATE certael_region_transfer_grants SET redeemed_at=$2,redeemed_by=$3,
                destination_server=$4,destination_fencing_epoch=$5
            WHERE grant_id=$1 AND redeemed_at IS NULL
            """;
        await using (var command = new NpgsqlCommand(redeem, connection, transaction))
        {
            command.Parameters.AddWithValue(grant.GrantId); command.Parameters.AddWithValue(now);
            command.Parameters.AddWithValue(actor); command.Parameters.AddWithValue(destinationServer);
            command.Parameters.AddWithValue(nextEpoch);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        await Audit(connection, transaction, grant.TenantId, grant.GameId, grant.EnvironmentId,
            grant.MatchId, "TransferGrantRedeemed", actor, nextEpoch,
            new { grant.GrantId, grant.PlayerSubject, grant.SourceRegion,
                grant.DestinationRegion, destinationServer }, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(grant.TenantId, grant.GameId, grant.EnvironmentId, grant.MatchId,
            grant.DestinationRegion, destinationServer, nextEpoch, nextExpiry);
    }

    private static bool StoredGrantMatches(NpgsqlDataReader reader, RegionTransferGrantV1 grant,
        SignedRegionTransferGrant signed) => reader.GetString(0) == grant.TenantId
        && reader.GetString(1) == grant.GameId && reader.GetString(2) == grant.EnvironmentId
        && reader.GetString(3) == grant.MatchId && reader.GetString(4) == grant.PlayerSubject
        && reader.GetString(5) == grant.SourceRegion && reader.GetString(6) == grant.DestinationRegion
        && reader.GetInt64(7) == grant.LeaseEpoch
        && CryptographicOperations.FixedTimeEquals((byte[])reader[8], SHA256.HashData(grant.Nonce))
        && CryptographicOperations.FixedTimeEquals((byte[])reader[9], signed.Digest)
        && reader.GetFieldValue<DateTimeOffset>(10).ToUnixTimeMilliseconds()
            == grant.IssuedAt.ToUnixTimeMilliseconds()
        && reader.GetFieldValue<DateTimeOffset>(11).ToUnixTimeMilliseconds()
            == grant.ExpiresAt.ToUnixTimeMilliseconds();

    private static void ValidateLease(RegionalLeaseV1 lease)
    {
        ValidateIdentifiers(lease.TenantId, lease.GameId, lease.EnvironmentId, lease.MatchId,
            lease.OwnerRegion, lease.OwnerServer);
        if (lease.FencingEpoch < 1) throw new ArgumentException("Lease epoch is invalid.");
    }
    private static void ValidateIdentifiers(params string[] values)
    {
        if (values.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not ('.' or '_' or '-' or ':'))))
            throw new ArgumentException("Coordinator identifier is invalid.");
    }
    private static void AddKey(NpgsqlCommand command, string tenant, string game,
        string environment, string match)
    {
        command.Parameters.AddWithValue(tenant); command.Parameters.AddWithValue(game);
        command.Parameters.AddWithValue(environment); command.Parameters.AddWithValue(match);
    }
    private static void AddLease(NpgsqlCommand command, RegionalLeaseV1 lease)
    {
        AddKey(command, lease.TenantId, lease.GameId, lease.EnvironmentId, lease.MatchId);
        command.Parameters.AddWithValue(lease.OwnerRegion); command.Parameters.AddWithValue(lease.OwnerServer);
        command.Parameters.AddWithValue(lease.FencingEpoch);
    }
    private static async ValueTask<DateTimeOffset> DatabaseNow(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT clock_timestamp()", connection, transaction);
        return (DateTimeOffset)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Control database time is unavailable."));
    }
    private static async ValueTask Audit(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenant, string game, string environment,
        string match, string action, string actor, long epoch, object details,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_coordinator_audit
                (audit_id,tenant_id,game_id,environment_id,match_id,action,actor,
                 fencing_epoch,details)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(Guid.NewGuid()); command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(game); command.Parameters.AddWithValue(environment);
        command.Parameters.AddWithValue(match); command.Parameters.AddWithValue(action);
        command.Parameters.AddWithValue(actor); command.Parameters.AddWithValue(epoch);
        command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(details));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
