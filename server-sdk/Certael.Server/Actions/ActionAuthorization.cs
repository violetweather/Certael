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
    ReadOnlyMemory<byte> EphemeralPublicKey,
    DateTimeOffset? AbsoluteExpiresAt = null,
    DateTimeOffset? RevokedAt = null,
    string SigningKeyId = "legacy",
    string ProtectionProfileId = "legacy",
    uint ProtocolMinimum = 1,
    uint ProtocolMaximum = 1);

public static class SessionBindingDigest
{
    public static byte[] Compute(SessionAuthorization session)
    {
        using var stream = new MemoryStream();
        Write(stream, session.SessionId); Write(stream, session.TenantId);
        Write(stream, session.GameId); Write(stream, session.EnvironmentId);
        Write(stream, session.PlayerSubject); Write(stream, session.MatchId);
        Write(stream, session.AuthoritativeServerId); Write(stream, session.BuildId);
        Write(stream, session.ProtectionProfileId); Write(stream, session.SigningKeyId);
        Write(stream, session.ProtocolMinimum); Write(stream, session.ProtocolMaximum);
        return SHA256.HashData(stream.ToArray());
    }

    private static void Write(Stream stream, string value)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)bytes.Length));
        stream.Write(length); stream.Write(bytes);
    }

    private static void Write(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }
}

public interface ISessionAuthorizationStore
{
    ValueTask<SessionAuthorization?> FindAsync(string tenantId, string sessionId, CancellationToken cancellationToken);
}

public interface ISessionAuthorizationWriter
{
    ValueTask CreateAsync(SessionAuthorization session, CancellationToken cancellationToken);
    ValueTask<bool> RenewAsync(string tenantId, string sessionId, string authoritativeServerId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken);
    ValueTask<bool> RevokeAsync(string tenantId, string sessionId, string authoritativeServerId,
        DateTimeOffset revokedAt, CancellationToken cancellationToken);
}

public sealed record SessionRevocationSelector(
    string TenantId, string EnvironmentId, string? GameId = null, string? BuildId = null,
    string? SigningKeyId = null, string? AuthoritativeServerId = null);

public interface ISessionAdministrationStore
{
    ValueTask<int> RevokeMatchingAsync(SessionRevocationSelector selector,
        DateTimeOffset revokedAt, CancellationToken cancellationToken);
}

public sealed class InMemorySessionAuthorizationStore : ISessionAuthorizationStore,
    ISessionAuthorizationWriter, ISessionAdministrationStore
{
    private readonly ConcurrentDictionary<string, SessionAuthorization> _sessions = new(StringComparer.Ordinal);
    public ValueTask<SessionAuthorization?> FindAsync(string tenantId, string sessionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SessionAuthorization? value = _sessions.GetValueOrDefault(sessionId);
        return ValueTask.FromResult(value?.TenantId == tenantId ? value : null);
    }
    public ValueTask CreateAsync(SessionAuthorization session, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_sessions.TryAdd(session.SessionId, session))
            throw new InvalidOperationException("Session already exists.");
        return ValueTask.CompletedTask;
    }
    public ValueTask<bool> RenewAsync(string tenantId, string sessionId, string authoritativeServerId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        while (_sessions.TryGetValue(sessionId, out SessionAuthorization? current))
        {
            if (current.TenantId != tenantId || current.AuthoritativeServerId != authoritativeServerId || current.RevokedAt is not null
                || current.AbsoluteExpiresAt is { } absolute && expiresAt > absolute)
                return ValueTask.FromResult(false);
            if (_sessions.TryUpdate(sessionId, current with { ExpiresAt = expiresAt }, current))
                return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }

    public ValueTask<bool> RevokeAsync(string tenantId, string sessionId, string authoritativeServerId,
        DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        while (_sessions.TryGetValue(sessionId, out SessionAuthorization? current))
        {
            if (current.TenantId != tenantId || current.AuthoritativeServerId != authoritativeServerId) return ValueTask.FromResult(false);
            if (current.RevokedAt is not null) return ValueTask.FromResult(true);
            if (_sessions.TryUpdate(sessionId, current with { RevokedAt = revokedAt }, current))
                return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }

    public ValueTask<int> RevokeMatchingAsync(SessionRevocationSelector selector,
        DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int count = 0;
        foreach ((string sessionId, SessionAuthorization current) in _sessions)
        {
            if (current.TenantId != selector.TenantId
                || current.EnvironmentId != selector.EnvironmentId
                || selector.GameId is not null && current.GameId != selector.GameId
                || selector.BuildId is not null && current.BuildId != selector.BuildId
                || selector.SigningKeyId is not null && current.SigningKeyId != selector.SigningKeyId
                || selector.AuthoritativeServerId is not null
                    && current.AuthoritativeServerId != selector.AuthoritativeServerId
                || current.RevokedAt is not null)
                continue;
            if (_sessions.TryUpdate(sessionId, current with { RevokedAt = revokedAt }, current))
                count++;
        }
        return ValueTask.FromResult(count);
    }
}

public interface IActionResultStore
{
    ValueTask<ActionResult<TResponse>?> FindAsync<TResponse>(string tenantId, string sessionId, Guid actionId, CancellationToken cancellationToken);
    ValueTask StoreAsync<TResponse>(string tenantId, string sessionId, ActionResult<TResponse> result, CancellationToken cancellationToken);
}

public sealed record ActionAdmission(
    string SessionId, string ActionType, ulong Sequence,
    ReadOnlyMemory<byte> PreviousDigest, ReadOnlyMemory<byte> ActionDigest,
    DateTimeOffset ReceivedAt, string TenantId = "legacy", string EnvironmentId = "legacy",
    ulong InitialSequence = 1);

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
        string stateKey = $"{admission.TenantId}\0{admission.EnvironmentId}\0{admission.SessionId}";
        State state = _states.GetOrAdd(stateKey, static _ => new State());
        lock (state.Gate)
        {
            if (state.HighestSequence is ulong highest && admission.Sequence <= highest)
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("REPLAY_OR_REORDER"));
            if ((state.HighestSequence is ulong prior
                    && (prior == ulong.MaxValue || admission.Sequence != prior + 1))
                || (state.HighestSequence is null && admission.Sequence != admission.InitialSequence))
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("SEQUENCE_GAP"));
            if (!CryptographicOperations.FixedTimeEquals(admission.PreviousDigest.Span, state.LastDigest))
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("ACTION_CHAIN_MISMATCH"));

            Queue<DateTimeOffset> rate = state.Rates.GetValueOrDefault(admission.ActionType)
                ?? AddRate(state, admission.ActionType);
            DateTimeOffset cutoff = admission.ReceivedAt - policy.Window;
            while (rate.TryPeek(out DateTimeOffset value) && value <= cutoff) rate.Dequeue();
            if (rate.Count >= policy.MaximumActions)
            {
                state.HighestSequence = admission.Sequence;
                state.LastDigest = admission.ActionDigest.ToArray();
                return ValueTask.FromResult(ActionAdmissionDecision.Reject("ACTION_RATE_LIMITED"));
            }

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
            || string.IsNullOrWhiteSpace(admission.TenantId) || string.IsNullOrWhiteSpace(admission.EnvironmentId)
            || admission.SessionId.Length > 128 || admission.ActionType.Length > 128
            || admission.TenantId.Length > 128 || admission.EnvironmentId.Length > 128
            || admission.Sequence == 0 || admission.InitialSequence == 0
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
        string expectedTenantId,
        string expectedGameId,
        string expectedEnvironmentId,
        string expectedMatchId,
        string expectedServerId,
        string expectedBuildId,
        CancellationToken cancellationToken)
        => await AuthorizeAsync(action, expectedActionType, expectedTenantId, expectedGameId,
            expectedEnvironmentId, expectedMatchId, expectedServerId, expectedBuildId,
            "", admissionPolicy ?? ActionAdmissionPolicy.Default, cancellationToken);

    public async ValueTask<AuthorizationDecision> AuthorizeAsync<TRequest>(
        AuthorizedAction<TRequest> action,
        string expectedActionType,
        string expectedTenantId,
        string expectedGameId,
        string expectedEnvironmentId,
        string expectedMatchId,
        string expectedServerId,
        string expectedBuildId,
        string expectedProtectionProfileId,
        ActionAdmissionPolicy actionPolicy,
        CancellationToken cancellationToken)
    {
        if (action.ActionId == Guid.Empty || action.ActionType != expectedActionType)
            return AuthorizationDecision.Reject("INVALID_ACTION");

        SessionAuthorization? session = await sessions.FindAsync(expectedTenantId, action.SessionId, cancellationToken);
        if (session is null) return AuthorizationDecision.Reject("INVALID_SESSION");
        if (session.RevokedAt is not null) return AuthorizationDecision.Reject("SESSION_REVOKED");
        if (session.ExpiresAt <= timeProvider.GetUtcNow()) return AuthorizationDecision.Reject("SESSION_EXPIRED");
        if (session.AbsoluteExpiresAt is { } absolute && absolute <= timeProvider.GetUtcNow())
            return AuthorizationDecision.Reject("SESSION_EXPIRED");
        if (session.ProtocolMinimum == 0 || session.ProtocolMaximum < session.ProtocolMinimum
            || action.ProtocolMajor < session.ProtocolMinimum
            || action.ProtocolMajor > session.ProtocolMaximum)
            return AuthorizationDecision.Reject("PROTOCOL_NOT_PERMITTED");
        if (session.TenantId != expectedTenantId || session.GameId != expectedGameId || session.EnvironmentId != expectedEnvironmentId
            || session.MatchId != expectedMatchId || session.AuthoritativeServerId != expectedServerId
            || session.BuildId != expectedBuildId
            || !string.IsNullOrEmpty(expectedProtectionProfileId)
                && session.ProtectionProfileId != expectedProtectionProfileId)
            return AuthorizationDecision.Reject("SESSION_BINDING_MISMATCH");
        byte[] expectedBindingDigest = SessionBindingDigest.Compute(session);
        if (action.SessionBindingDigest.Length != 32
            || !CryptographicOperations.FixedTimeEquals(action.SessionBindingDigest.Span, expectedBindingDigest))
            return AuthorizationDecision.Reject("SESSION_BINDING_MISMATCH");
        if (action.Sequence < session.MinimumSequence || action.Sequence > session.MaximumSequence)
            return AuthorizationDecision.Reject("SEQUENCE_OUT_OF_RANGE");
        if (!proofVerifier.Verify(action, session.EphemeralPublicKey.Span))
            return AuthorizationDecision.Reject("INVALID_POSSESSION_PROOF");
        byte[] actionDigest;
        try { actionDigest = SHA256.HashData(Ed25519ActionProofVerifier.Canonicalize(action)); }
        catch (ActionEnvelopeException) { return AuthorizationDecision.Reject("INVALID_ENVELOPE"); }
        ActionAdmissionDecision admission = await admissions.TryAdmitAsync(new ActionAdmission(
            action.SessionId, action.ActionType, action.Sequence, action.PreviousDigest,
            actionDigest, timeProvider.GetUtcNow(), expectedTenantId, expectedEnvironmentId,
            session.MinimumSequence), actionPolicy,
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
