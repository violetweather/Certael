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
            DateTimeOffset.UtcNow, 1, "request", ReadOnlyMemory<byte>.Empty, new byte[32], new byte[64]);

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        AuthorizationDecision crossMatch = await authorizer.AuthorizeAsync(action, "inventory.craft", "game", "prod", "other", "server", "build", cancellationToken);
        Assert.False(crossMatch.Allowed);
        Assert.Equal("SESSION_BINDING_MISMATCH", crossMatch.PublicReason);

        AuthorizationDecision crossBuild = await authorizer.AuthorizeAsync(action, "inventory.craft", "game", "prod", "match", "server", "other-build", cancellationToken);
        Assert.False(crossBuild.Allowed);
        Assert.Equal("SESSION_BINDING_MISMATCH", crossBuild.PublicReason);

        AuthorizationDecision first = await authorizer.AuthorizeAsync(action, "inventory.craft", "game", "prod", "match", "server", "build", cancellationToken);
        AuthorizationDecision replay = await authorizer.AuthorizeAsync(action, "inventory.craft", "game", "prod", "match", "server", "build", cancellationToken);
        Assert.True(first.Allowed);
        Assert.False(replay.Allowed);
        Assert.Equal("REPLAY_OR_REORDER", replay.PublicReason);
    }

    private sealed class AllowProofVerifier : IActionProofVerifier
    {
        public bool Verify<T>(AuthorizedAction<T> action, ReadOnlySpan<byte> key) => true;
    }

    private sealed class SingleSessionStore(SessionAuthorization session) : ISessionAuthorizationStore
    {
        public ValueTask<SessionAuthorization?> FindAsync(string id, CancellationToken cancellationToken) =>
            ValueTask.FromResult<SessionAuthorization?>(id == session.SessionId ? session : null);
    }
}
