using System.Collections.Concurrent;
using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class AuthoritativeActionHandlerTests
{
    [Fact]
    public async Task ConcurrentDuplicateCommitsExactlyOnce()
    {
        var session = new SessionAuthorization("s", "tenant", "game", "prod", "player", "match", "server", "build",
            DateTimeOffset.UtcNow.AddMinutes(5), 1, 100, new byte[32]);
        var store = new ResultStore();
        var transaction = new Transaction();
        var handler = new AuthoritativeActionHandler<string, string, int>(
            new ActionAuthorizer(new SessionStore(session), new InMemoryActionAdmissionStore(), new AllowProofVerifier(), TimeProvider.System),
            store,
            (_, _) => ValueTask.FromResult<IAuthoritativeTransaction<int>>(transaction),
            (action, _, _) => ValueTask.FromResult(RuleDecision<string>.Accept("committed",
                new AuthoritativeEvent(Guid.NewGuid(), action.ActionId, "test.committed", 1,
                    ReadOnlyMemory<byte>.Empty, DateTimeOffset.UtcNow))));
        Guid actionId = Guid.NewGuid();
        var action = new AuthorizedAction<string>("s", 1, actionId, "test.action", 1, DateTimeOffset.UtcNow,
            1, "request", ReadOnlyMemory<byte>.Empty, new byte[32], new byte[64]);
        var binding = new ActionBinding("test.action", "game", "prod", "match", "server", "build");
        CancellationToken token = TestContext.Current.CancellationToken;

        ActionResult<string>[] results = await Task.WhenAll(
            handler.HandleAsync(action, binding, token).AsTask(),
            handler.HandleAsync(action, binding, token).AsTask());

        Assert.All(results, result => Assert.Equal(ActionOutcome.Accepted, result.Outcome));
        Assert.Equal(1, transaction.Commits);
        Assert.Single(transaction.Events);
    }

    private sealed class AllowProofVerifier : IActionProofVerifier
    {
        public bool Verify<T>(AuthorizedAction<T> action, ReadOnlySpan<byte> key) => true;
    }

    private sealed class SessionStore(SessionAuthorization session) : ISessionAuthorizationStore
    {
        public ValueTask<SessionAuthorization?> FindAsync(string id, CancellationToken token) =>
            ValueTask.FromResult<SessionAuthorization?>(id == session.SessionId ? session : null);
    }

    private sealed class ResultStore : IActionResultStore
    {
        private readonly ConcurrentDictionary<Guid, object> _results = new();
        public ValueTask<ActionResult<T>?> FindAsync<T>(string sessionId, Guid id, CancellationToken token) =>
            ValueTask.FromResult(_results.TryGetValue(id, out object? value) ? (ActionResult<T>)value : null);
        public ValueTask StoreAsync<T>(string sessionId, ActionResult<T> result, CancellationToken token)
        { _results[result.ActionId] = result; return ValueTask.CompletedTask; }
    }

    private sealed class Transaction : IAuthoritativeTransaction<int>
    {
        public int Current => 0;
        public ulong Revision => 0;
        public int Commits { get; private set; }
        public List<AuthoritativeEvent> Events { get; } = [];
        public ValueTask<ActionReservation<T>> ReserveActionAsync<T>(Guid actionId, CancellationToken token) =>
            ValueTask.FromResult(ActionReservation<T>.New());
        public ValueTask StageActionResultAsync<T>(ActionResult<T> result, CancellationToken token) =>
            ValueTask.CompletedTask;
        public void EnqueueAuthoritativeEvent(AuthoritativeEvent authoritativeEvent) => Events.Add(authoritativeEvent);
        public ValueTask<(int State, ulong Revision)> CommitAsync(CancellationToken token)
        { Commits++; return ValueTask.FromResult((1, 1UL)); }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
