using Certael.Server.Actions;
using Certael.Server.Sessions;

namespace Certael.Server.Tests;

public sealed class SessionLifecycleTests
{
    [Fact]
    public async Task RevocationIsIdempotentAndRenewalCannotExceedAbsoluteLifetime()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var store = new InMemorySessionAuthorizationStore();
        var session = new SessionAuthorization("s", "tenant", "game", "prod", "player", "match",
            "server", "build", now.AddMinutes(30), 1, 100, new byte[32], now.AddHours(1));
        CancellationToken token = TestContext.Current.CancellationToken;
        await store.CreateAsync(session, token);
        Assert.False(await store.RenewAsync("tenant", "s", "server", now.AddHours(2), token));
        Assert.True(await store.RevokeAsync("tenant", "s", "server", now, token));
        Assert.True(await store.RevokeAsync("tenant", "s", "server", now.AddSeconds(1), token));
        Assert.False(await store.RenewAsync("tenant", "s", "server", now.AddMinutes(45), token));
    }

    [Fact]
    public void KeyRingSupportsOverlapAndRevocation()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var oldKey = System.Security.Cryptography.ECDsa.Create();
        using var newKey = System.Security.Cryptography.ECDsa.Create();
        var ring = new BootstrapSigningKeyRing([
            new("old", oldKey, now.AddDays(-1), now.AddDays(1)),
            new("new", newKey, now.AddMinutes(-1), now.AddDays(2))
        ], "new");
        Assert.Equal("new", ring.Active(now).KeyId);
        Assert.NotNull(ring.Verification("old", now));
        Assert.Null(ring.Verification("missing", now));

        using var scopedKey = System.Security.Cryptography.ECDsa.Create();
        var scoped = new BootstrapSigningKeyRing([
            new BootstrapSigningKey("scoped", scopedKey, now.AddMinutes(-1), now.AddHours(1),
                TenantId: "tenant-a", EnvironmentId: "prod")
        ], "scoped");
        Assert.Equal("scoped", scoped.Active(now, "tenant-a", "prod").KeyId);
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            scoped.Active(now, "tenant-b", "prod"));
    }

    [Fact]
    public async Task EmergencyRevocationIsTenantBoundAndSelectorScoped()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var store = new InMemorySessionAuthorizationStore();
        CancellationToken token = TestContext.Current.CancellationToken;
        foreach (SessionAuthorization session in new[]
        {
            Session("one", "tenant", "prod", "bad-build", "key-a", now),
            Session("two", "tenant", "prod", "good-build", "key-a", now),
            Session("three", "other", "prod", "bad-build", "key-a", now)
        })
            await store.CreateAsync(session, token);

        int revoked = await store.RevokeMatchingAsync(
            new SessionRevocationSelector("tenant", "prod", BuildId: "bad-build"), now, token);
        Assert.Equal(1, revoked);
        Assert.NotNull((await store.FindAsync("tenant", "one", token))!.RevokedAt);
        Assert.Null((await store.FindAsync("tenant", "two", token))!.RevokedAt);
        Assert.Null((await store.FindAsync("other", "three", token))!.RevokedAt);
    }

    private static SessionAuthorization Session(string id, string tenant, string environment,
        string build, string key, DateTimeOffset now) =>
        new(id, tenant, "game", environment, "player", "match", "server", build,
            now.AddMinutes(30), 1, 100, new byte[32], now.AddHours(1), null, key);
}
