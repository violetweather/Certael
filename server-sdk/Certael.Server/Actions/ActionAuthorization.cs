using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Certael.Server.Actions;

public sealed record SessionAuthorization(
    string SessionId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string PlayerSubject,
    string MatchId,
    string AuthoritativeServerId,
    string BuildId,
    DateTimeOffset ExpiresAt,
    ulong MinimumSequence,
    ulong MaximumSequence,
    ReadOnlyMemory<byte> EphemeralPublicKey);

public interface ISessionAuthorizationStore
{
    ValueTask<SessionAuthorization?> FindAsync(string sessionId, CancellationToken cancellationToken);
}

public interface ISessionAuthorizationWriter
{
    ValueTask CreateAsync(SessionAuthorization session, CancellationToken cancellationToken);
    ValueTask<bool> RenewAsync(string sessionId, string authoritativeServerId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

public sealed class InMemorySessionAuthorizationStore : ISessionAuthorizationStore, ISessionAuthorizationWriter
{
    private readonly ConcurrentDictionary<string, SessionAuthorization> _sessions = new(StringComparer.Ordinal);
    public ValueTask<SessionAuthorization?> FindAsync(string sessionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_sessions.GetValueOrDefault(sessionId));
    }
    public ValueTask CreateAsync(SessionAuthorization session, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_sessions.TryAdd(session.SessionId, session))
            throw new InvalidOperationException("Session already exists.");
        return ValueTask.CompletedTask;
    }
    public ValueTask<bool> RenewAsync(string sessionId, string authoritativeServerId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        while (_sessions.TryGetValue(sessionId, out SessionAuthorization? current))
        {
            if (current.AuthoritativeServerId != authoritativeServerId) return ValueTask.FromResult(false);
            if (_sessions.TryUpdate(sessionId, current with { ExpiresAt = expiresAt }, current))
                return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }
}

public interface IActionResultStore
{
    ValueTask<ActionResult<TResponse>?> FindAsync<TResponse>(string sessionId, Guid actionId, CancellationToken cancellationToken);
    ValueTask StoreAsync<TResponse>(string sessionId, ActionResult<TResponse> result, CancellationToken cancellationToken);
}

public sealed record ActionAdmission(
    string SessionId, string ActionType, ulong Sequence,
    ReadOnlyMemory<byte> PreviousDigest, ReadOnlyMemory<byte> ActionDigest,
    DateTimeOffset ReceivedAt);

public sealed record ActionAdmissionPolicy(int MaximumActions, TimeSpan Window)
{
    public static ActionAdmissionPolicy Default { get; } = new(120, TimeSpan.FromSeconds(10));
}

public sealed record ActionAdmissionDecision(bool Allowed, string PublicReason)
{
    public static ActionAdmissionDecision Allow() => new(true, "ALLOWED");
    public static ActionAdmissionDecision Reject(string reason) => new(false, reason);
}

/// <summary>Atomically enforces sequence, hash-chain continuity, and per-action rate.</summary>
public interface IActionAdmissionStore
{
    ValueTask<ActionAdmissionDecision> TryAdmitAsync(ActionAdmission admission,
        ActionAdmissionPolicy policy, CancellationToken cancellationToken);
}

public sealed class InMemoryActionAdmissionStore : IActionAdmissionStore
{
    private sealed class State
    {
        public readonly object Gate = new();
        public ulong? HighestSequence;
        public byte[] LastDigest = new byte[32];
        public readonly Dictionary<string, Queue<DateTimeOffset>> Rates = new(StringComparer.Ordinal);
    }

    private readonly ConcurrentDictionary<string, State> _states = new(StringComparer.Ordinal);

    public ValueTask<ActionAdmissionDecision> TryAdmitAsync(ActionAdmission admission,
        ActionAdmissionPolicy policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Validate(admission, policy);
        State state = _states.GetOrAdd(admission.SessionId, static _ => new State());
        lock (state.Gate)
        {
            if (state.HighestSequence is ulong highest && admission.Sequence <= highest)
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("REPLAY_OR_REORDER"));
            if (!CryptographicOperations.FixedTimeEquals(admission.PreviousDigest.Span, state.LastDigest))
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("ACTION_CHAIN_MISMATCH"));

            Queue<DateTimeOffset> rate = state.Rates.GetValueOrDefault(admission.ActionType)
                ?? AddRate(state, admission.ActionType);
            DateTimeOffset cutoff = admission.ReceivedAt - policy.Window;
            while (rate.TryPeek(out DateTimeOffset value) && value <= cutoff) rate.Dequeue();
            if (rate.Count >= policy.MaximumActions)
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("ACTION_RATE_LIMITED"));

            rate.Enqueue(admission.ReceivedAt);
            state.HighestSequence = admission.Sequence;
            state.LastDigest = admission.ActionDigest.ToArray();
            return ValueTask.FromResult(ActionAdmissionDecision.Allow());
        }
    }

    private static Queue<DateTimeOffset> AddRate(State state, string actionType)
    {
        var value = new Queue<DateTimeOffset>();
        state.Rates.Add(actionType, value);
        return value;
    }

    public static void Validate(ActionAdmission admission, ActionAdmissionPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(admission.SessionId) || string.IsNullOrWhiteSpace(admission.ActionType)
            || admission.PreviousDigest.Length != 32 || admission.ActionDigest.Length != 32)
            throw new ArgumentException("Action admission is invalid.", nameof(admission));
        if (policy.MaximumActions is < 1 or > 100_000 || policy.Window <= TimeSpan.Zero
            || policy.Window > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(policy));
    }
}

public sealed class ActionAuthorizer(
    ISessionAuthorizationStore sessions,
    IActionAdmissionStore admissions,
    IActionProofVerifier proofVerifier,
    TimeProvider timeProvider,
    ActionAdmissionPolicy? admissionPolicy = null)
{
    public async ValueTask<AuthorizationDecision> AuthorizeAsync<TRequest>(
        AuthorizedAction<TRequest> action,
        string expectedActionType,
        string expectedGameId,
        string expectedEnvironmentId,
        string expectedMatchId,
        string expectedServerId,
        string expectedBuildId,
        CancellationToken cancellationToken)
    {
        if (action.ActionId == Guid.Empty || action.ActionType != expectedActionType)
            return AuthorizationDecision.Reject("INVALID_ACTION");

        SessionAuthorization? session = await sessions.FindAsync(action.SessionId, cancellationToken);
        if (session is null) return AuthorizationDecision.Reject("INVALID_SESSION");
        if (session.ExpiresAt <= timeProvider.GetUtcNow()) return AuthorizationDecision.Reject("SESSION_EXPIRED");
        if (session.GameId != expectedGameId || session.EnvironmentId != expectedEnvironmentId
            || session.MatchId != expectedMatchId || session.AuthoritativeServerId != expectedServerId
            || session.BuildId != expectedBuildId)
            return AuthorizationDecision.Reject("SESSION_BINDING_MISMATCH");
        if (action.Sequence < session.MinimumSequence || action.Sequence > session.MaximumSequence)
            return AuthorizationDecision.Reject("SEQUENCE_OUT_OF_RANGE");
        if (!proofVerifier.Verify(action, session.EphemeralPublicKey.Span))
            return AuthorizationDecision.Reject("INVALID_POSSESSION_PROOF");
        byte[] actionDigest = SHA256.HashData(Ed25519ActionProofVerifier.Canonicalize(action));
        ActionAdmissionDecision admission = await admissions.TryAdmitAsync(new ActionAdmission(
            action.SessionId, action.ActionType, action.Sequence, action.PreviousDigest,
            actionDigest, timeProvider.GetUtcNow()), admissionPolicy ?? ActionAdmissionPolicy.Default,
            cancellationToken);
        if (!admission.Allowed) return AuthorizationDecision.Reject(admission.PublicReason);
        return AuthorizationDecision.Allow(session);
    }
}

public sealed record AuthorizationDecision(bool Allowed, string PublicReason, SessionAuthorization? Session)
{
    public static AuthorizationDecision Allow(SessionAuthorization session) => new(true, "ALLOWED", session);
    public static AuthorizationDecision Reject(string reason) => new(false, reason, null);
}
