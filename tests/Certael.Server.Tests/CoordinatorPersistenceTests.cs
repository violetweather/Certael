extern alias coordinator;

using System.Security.Cryptography;
using Certael.Server.Sessions;
using Npgsql;
using CoordinatorStore = coordinator::Certael.Coordinator.CoordinatorStore;

namespace Certael.Server.Tests;

[Collection("Persistence")]
public sealed class CoordinatorPersistenceTests
{
    [Fact]
    [Trait("Category", "Integration")]
    public async Task TransferAndFailoverNeverCreateTwoOwnersOrRedeemTwice()
    {
        string? connection = Environment.GetEnvironmentVariable("CERTAEL_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connection))
        { Assert.Skip("CERTAEL_TEST_POSTGRES is not configured."); return; }
        await using NpgsqlDataSource source = NpgsqlDataSource.Create(connection);
        await ApplyMigrations(source);
        var store = new CoordinatorStore(source);
        string suffix = Guid.NewGuid().ToString("N");
        string tenant = $"tenant-{suffix}", match = $"match-{suffix}";
        try
        {
            RegionalLeaseV1 east = (await store.AcquireAsync(tenant, "game", "test", match,
                "us-east", "server-east", false, "server-east",
                TestContext.Current.CancellationToken))!;
            Assert.Equal(1, east.FencingEpoch);
            Assert.Null(await store.AcquireAsync(tenant, "game", "test", match,
                "us-east", "another-server", false, "another-server",
                TestContext.Current.CancellationToken));
            Assert.Null(await store.AcquireAsync(tenant, "game", "test", match,
                "us-west", "server-west", false, "server-west",
                TestContext.Current.CancellationToken));

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var signer = new RegionTransferGrantSigner(key, "key-1");
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var grant = new RegionTransferGrantV1(Guid.NewGuid(), tenant, "game", "test",
                match, "player", "us-east", "us-west", east.FencingEpoch,
                RandomNumberGenerator.GetBytes(32), now, now.AddSeconds(60));
            SignedRegionTransferGrant signed = signer.Sign(grant);
            Assert.True(await store.RecordGrantIfOwnerAsync(east, grant, signed,
                "server-east", TestContext.Current.CancellationToken));
            Assert.True(await store.ReleaseAsync(east, "server-east",
                TestContext.Current.CancellationToken));
            RegionalLeaseV1 west = (await store.RedeemAsync(grant, signed, "server-west",
                "server-west", TestContext.Current.CancellationToken))!;
            Assert.Equal(2, west.FencingEpoch);
            Assert.Equal("us-west", west.OwnerRegion);
            Assert.Null(await store.RedeemAsync(grant, signed, "server-west",
                "server-west", TestContext.Current.CancellationToken));
            Assert.False(await store.IsCurrentOwnerAsync(east,
                TestContext.Current.CancellationToken));
            Assert.True(await store.IsCurrentOwnerAsync(west,
                TestContext.Current.CancellationToken));

            RegionalLeaseV1 failover = (await store.AcquireAsync(tenant, "game", "test",
                match, "eu-central", "server-eu", true, "operator",
                TestContext.Current.CancellationToken))!;
            Assert.Equal(3, failover.FencingEpoch);
            Assert.False(await store.IsCurrentOwnerAsync(west,
                TestContext.Current.CancellationToken));
            Assert.False(await store.ReleaseAsync(east, "server-east",
                TestContext.Current.CancellationToken));
        }
        finally { await DeleteScope(source, tenant); }
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task GrantCannotRedeemAfterAForcedEpochChange()
    {
        string? connection = Environment.GetEnvironmentVariable("CERTAEL_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connection))
        { Assert.Skip("CERTAEL_TEST_POSTGRES is not configured."); return; }
        await using NpgsqlDataSource source = NpgsqlDataSource.Create(connection);
        await ApplyMigrations(source);
        var store = new CoordinatorStore(source); string suffix = Guid.NewGuid().ToString("N");
        string tenant = $"tenant-{suffix}", match = $"match-{suffix}";
        try
        {
            RegionalLeaseV1 sourceLease = (await store.AcquireAsync(tenant, "game", "test",
                match, "source", "source-server", false, "source-server",
                TestContext.Current.CancellationToken))!;
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var grant = new RegionTransferGrantV1(Guid.NewGuid(), tenant, "game", "test",
                match, "player", "source", "destination", sourceLease.FencingEpoch,
                RandomNumberGenerator.GetBytes(32), now, now.AddSeconds(60));
            SignedRegionTransferGrant signed = new RegionTransferGrantSigner(key, "key").Sign(grant);
            Assert.True(await store.RecordGrantIfOwnerAsync(sourceLease, grant, signed,
                "source-server", TestContext.Current.CancellationToken));
            _ = await store.AcquireAsync(tenant, "game", "test", match, "recovery",
                "recovery-server", true, "operator", TestContext.Current.CancellationToken);
            Assert.Null(await store.RedeemAsync(grant, signed, "destination-server",
                "destination-server", TestContext.Current.CancellationToken));
        }
        finally { await DeleteScope(source, tenant); }
    }

    private static async Task ApplyMigrations(NpgsqlDataSource source)
    {
        string root = RepositoryRoot();
        await using NpgsqlConnection connection = await source.OpenConnectionAsync();
        foreach (string path in Directory.GetFiles(Path.Combine(root, "backend",
                     "Certael.Coordinator", "Migrations"), "*.sql").Order())
        {
            await using var command = new NpgsqlCommand(await File.ReadAllTextAsync(path), connection);
            await command.ExecuteNonQueryAsync();
        }
    }
    private static async Task DeleteScope(NpgsqlDataSource source, string tenant)
    {
        await using NpgsqlConnection connection = await source.OpenConnectionAsync();
        foreach (string table in new[] { "certael_coordinator_audit",
                     "certael_region_transfer_grants", "certael_match_leases" })
        {
            await using var command = new NpgsqlCommand($"DELETE FROM {table} WHERE tenant_id=$1",
                connection); command.Parameters.AddWithValue(tenant); await command.ExecuteNonQueryAsync();
        }
    }
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Cargo.toml"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new InvalidOperationException("Repository root was not found.");
    }
}
