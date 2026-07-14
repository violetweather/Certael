using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Certael.Server.Agent;

public sealed class InMemoryAgentSessionStore(TimeProvider clock) : IAgentSessionStore
{
    private readonly ConcurrentDictionary<string, Entry> _sessions = new(StringComparer.Ordinal);

    public ValueTask CreateAsync(VerifiedAgentSession session, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSession(session);
        if (!_sessions.TryAdd(Key(session.TenantId, session.AgentSessionId), new Entry(Clone(session))))
            throw new InvalidOperationException("Agent session already exists.");
        return ValueTask.CompletedTask;
    }

    public ValueTask<VerifiedAgentSession?> FindAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_sessions.TryGetValue(Key(tenantId, agentSessionId), out Entry? entry))
            return ValueTask.FromResult<VerifiedAgentSession?>(null);
        lock (entry.Sync)
            return ValueTask.FromResult<VerifiedAgentSession?>(entry.RevokedAt is null
                ? Clone(entry.Session) : null);
    }

    public ValueTask<AgentSessionAdmission?> FindAdmissionAsync(string tenantId,
        string agentSessionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_sessions.TryGetValue(Key(tenantId, agentSessionId), out Entry? entry))
            return ValueTask.FromResult<AgentSessionAdmission?>(null);
        lock (entry.Sync)
            return ValueTask.FromResult<AgentSessionAdmission?>(entry.RevokedAt is null
                && entry.Challenge is not null && entry.ChallengeExpiresAt is not null
                ? new(Clone(entry.Session), entry.Challenge.ToArray(), entry.ChallengeExpiresAt.Value)
                : null);
    }

    public ValueTask<AgentStoredHealth?> HealthAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_sessions.TryGetValue(Key(tenantId, agentSessionId), out Entry? entry))
            return ValueTask.FromResult<AgentStoredHealth?>(null);
        lock (entry.Sync)
            return ValueTask.FromResult<AgentStoredHealth?>(new(entry.Session.AgentSessionId,
                entry.Session.EnvironmentId, entry.Session.AuthoritativeServerId,
                entry.Session.ExpiresAt, entry.LastReportAt, entry.RevokedAt));
    }

    public ValueTask<bool> SetChallengeAsync(string tenantId, string agentSessionId,
        byte[] challenge, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (challenge.Length is < 16 or > 256) throw new ArgumentException("Challenge is invalid.");
        if (!_sessions.TryGetValue(Key(tenantId, agentSessionId), out Entry? entry))
            return ValueTask.FromResult(false);
        lock (entry.Sync)
        {
            DateTimeOffset now = clock.GetUtcNow();
            if (entry.RevokedAt is not null || entry.Session.ExpiresAt <= now
                || expiresAt <= now || expiresAt > now.AddMinutes(2))
                return ValueTask.FromResult(false);
            entry.Challenge = challenge.ToArray();
            entry.ChallengeExpiresAt = expiresAt;
            return ValueTask.FromResult(true);
        }
    }

    public ValueTask<bool> CommitReportAsync(string tenantId, AgentIntegrityReport report,
        byte[] canonicalReport, byte[] reportDigest, DateTimeOffset acceptedAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (canonicalReport.Length is < 1 or > AgentReportCodec.MaximumReport
            || reportDigest.Length != 32)
            throw new ArgumentException("Canonical Agent report is invalid.");
        if (!_sessions.TryGetValue(Key(tenantId, report.AgentSessionId), out Entry? entry))
            return ValueTask.FromResult(false);
        lock (entry.Sync)
        {
            if (entry.RevokedAt is not null || entry.Session.ExpiresAt <= acceptedAt
                || entry.Challenge is null || entry.ChallengeExpiresAt <= acceptedAt
                || report.Sequence != entry.Session.LastSequence + 1
                || !CryptographicOperations.FixedTimeEquals(
                    report.PreviousReportDigest, entry.Session.LastReportDigest)
                || !CryptographicOperations.FixedTimeEquals(report.ChallengeNonce, entry.Challenge))
                return ValueTask.FromResult(false);
            entry.Session = entry.Session with
            {
                LastSequence = report.Sequence,
                LastReportDigest = reportDigest.ToArray()
            };
            entry.LastReportAt = acceptedAt;
            entry.Challenge = null;
            entry.ChallengeExpiresAt = null;
            return ValueTask.FromResult(true);
        }
    }

    public ValueTask<bool> RevokeAsync(string tenantId, string agentSessionId, string reason,
        DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 512 || reason.Any(char.IsControl))
            throw new ArgumentException("Revocation reason is invalid.");
        if (!_sessions.TryGetValue(Key(tenantId, agentSessionId), out Entry? entry))
            return ValueTask.FromResult(false);
        lock (entry.Sync)
        {
            if (entry.RevokedAt is not null) return ValueTask.FromResult(false);
            entry.RevokedAt = revokedAt;
            entry.Challenge = null;
            entry.ChallengeExpiresAt = null;
            return ValueTask.FromResult(true);
        }
    }

    public ValueTask<AgentPlayerDeletionResult> DeletePlayerAsync(string tenantId,
        string environmentId, string playerSubject, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(environmentId)
            || string.IsNullOrWhiteSpace(playerSubject))
            throw new ArgumentException("Tenant, environment, and player subject are required.");
        int removed = 0;
        foreach ((string key, Entry entry) in _sessions)
        {
            if (!string.Equals(entry.Session.TenantId, tenantId, StringComparison.Ordinal)
                || !string.Equals(entry.Session.EnvironmentId, environmentId,
                    StringComparison.Ordinal)
                || !string.Equals(entry.Session.PlayerSubject, playerSubject,
                    StringComparison.Ordinal))
                continue;
            if (_sessions.TryRemove(key, out _)) removed++;
        }
        return ValueTask.FromResult(new AgentPlayerDeletionResult(removed, 0));
    }

    private static string Key(string tenantId, string sessionId) => $"{tenantId.Length}:{tenantId}{sessionId}";

    private static VerifiedAgentSession Clone(VerifiedAgentSession value) => value with
    {
        AgentPublicKey = value.AgentPublicKey.ToArray(),
        LastReportDigest = value.LastReportDigest.ToArray()
    };

    private static void ValidateSession(VerifiedAgentSession session)
    {
        if (string.IsNullOrWhiteSpace(session.TenantId)
            || string.IsNullOrWhiteSpace(session.AgentSessionId)
            || string.IsNullOrWhiteSpace(session.AuthoritativeServerId)
            || session.AgentPublicKey.Length != 32 || session.LastReportDigest.Length != 32)
            throw new ArgumentException("Agent session is invalid.");
    }

    private sealed class Entry(VerifiedAgentSession session)
    {
        internal object Sync { get; } = new();
        internal VerifiedAgentSession Session { get; set; } = session;
        internal byte[]? Challenge { get; set; }
        internal DateTimeOffset? ChallengeExpiresAt { get; set; }
        internal DateTimeOffset? LastReportAt { get; set; }
        internal DateTimeOffset? RevokedAt { get; set; }
    }
}
