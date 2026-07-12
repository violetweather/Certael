using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class ActionAuthorizerTests
{
    [Fact]
    public async Task RejectsCrossMatchAndReplay()
    {
        var session = new SessionAuthorization("s", "tenant", "game", "prod", "player", "match", "server", "build",
            DateTimeOffset.UtcNow.AddMinutes(5), 1, 100, new byte[32]);
        var authorizer = new ActionAuthorizer(new SingleSessionStore(session), new InMemoryActionAdmissionStore(), new AllowProofVerifier(), TimeProvider.System);
        var action = new AuthorizedAction<string>("s", 1, Guid.NewGuid(), "inventory.craft", 1,
            DateTimeOffset.UtcNow, 1, "request", ReadOnlyMemory<byte>.Empty, new byte[32], new byte[64],
            RequestSchema: "test.Request.v1", SessionBindingDigest: SessionBindingDigest.Compute(session));

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        AuthorizationDecision crossMatch = await authorizer.AuthorizeAsync(action, "inventory.craft", "tenant", "game", "prod", "other", "server", "build", cancellationToken);
        Assert.False(crossMatch.Allowed);
        Assert.Equal("SESSION_BINDING_MISMATCH", crossMatch.PublicReason);

        AuthorizationDecision crossBuild = await authorizer.AuthorizeAsync(action, "inventory.craft", "tenant", "game", "prod", "match", "server", "other-build", cancellationToken);
        Assert.False(crossBuild.Allowed);
        Assert.Equal("SESSION_BINDING_MISMATCH", crossBuild.PublicReason);

        AuthorizationDecision first = await authorizer.AuthorizeAsync(action, "inventory.craft", "tenant", "game", "prod", "match", "server", "build", cancellationToken);
        AuthorizationDecision replay = await authorizer.AuthorizeAsync(action, "inventory.craft", "tenant", "game", "prod", "match", "server", "build", cancellationToken);
        Assert.True(first.Allowed);
        Assert.False(replay.Allowed);
        Assert.Equal("REPLAY_OR_REORDER", replay.PublicReason);
    }

    [Fact]
    public async Task RequiresContiguousSequenceAndRateRejectionConsumesValidAction()
    {
        var store = new InMemoryActionAdmissionStore();
        var policy = new ActionAdmissionPolicy(1, TimeSpan.FromMinutes(1));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        byte[] zero = new byte[32], first = new byte[32], second = new byte[32], third = new byte[32];
        first[0] = 1; second[0] = 2; third[0] = 3;
        CancellationToken token = TestContext.Current.CancellationToken;

        Assert.True((await store.TryAdmitAsync(new("s", "action", 1, zero, first, now), policy, token)).Allowed);
        Assert.Equal("ACTION_RATE_LIMITED", (await store.TryAdmitAsync(
            new("s", "action", 2, first, second, now), policy, token)).PublicReason);
        Assert.Equal("ACTION_RATE_LIMITED", (await store.TryAdmitAsync(
            new("s", "action", 3, second, third, now), policy, token)).PublicReason);
        Assert.Equal("SEQUENCE_GAP", (await store.TryAdmitAsync(
            new("s", "action", 5, third, zero, now), policy, token)).PublicReason);
    }

    private sealed class AllowProofVerifier : IActionProofVerifier
    {
        public bool Verify<T>(AuthorizedAction<T> action, ReadOnlySpan<byte> key) => true;
    }

    private sealed class SingleSessionStore(SessionAuthorization session) : ISessionAuthorizationStore
    {
        public ValueTask<SessionAuthorization?> FindAsync(string tenant, string id, CancellationToken cancellationToken) =>
            ValueTask.FromResult<SessionAuthorization?>(tenant == session.TenantId && id == session.SessionId ? session : null);
    }
}
