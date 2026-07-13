using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Certael.Server.Agent;

public sealed record AgentReportChallenge(
    string AgentSessionId, byte[] Nonce, DateTimeOffset ExpiresAt);

public sealed record AgentSessionHealth(
    string AgentSessionId, string State, DateTimeOffset? LastReportAt,
    IReadOnlyList<string> PublicReasons);

public interface IAgentSessionLifecycle
{
    void Register(VerifiedAgentSession session);
    AgentReportChallenge IssueChallenge(string agentSessionId);
    AgentReportDecision Submit(AgentIntegrityReport report, DateTimeOffset now);
    AgentSessionHealth Health(string agentSessionId, DateTimeOffset now);
    bool Revoke(string agentSessionId, string reason, DateTimeOffset now);
}

/// <summary>
/// Development and conformance implementation. Production deployments must use
/// an atomic distributed store with the same transition semantics.
/// </summary>
public sealed class InMemoryAgentSessionLifecycle(
    AgentReportVerifier verifier,
    TimeProvider timeProvider) : IAgentSessionLifecycle
{
    private readonly ConcurrentDictionary<string, State> _sessions = new(StringComparer.Ordinal);

    public void Register(VerifiedAgentSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!_sessions.TryAdd(session.AgentSessionId, new State(session)))
            throw new InvalidOperationException("Agent session already exists.");
    }

    public AgentReportChallenge IssueChallenge(string agentSessionId)
    {
        if (!_sessions.TryGetValue(agentSessionId, out State? state))
            throw new KeyNotFoundException("Agent session was not found.");
        lock (state.Gate)
        {
            DateTimeOffset now = timeProvider.GetUtcNow();
            if (state.RevokedAt is not null || state.Session.ExpiresAt <= now)
                throw new InvalidOperationException("Agent session is not active.");
            byte[] nonce = RandomNumberGenerator.GetBytes(32);
            DateTimeOffset expiresAt = now.AddSeconds(30);
            state.Challenge = nonce;
            state.ChallengeExpiresAt = expiresAt;
            return new AgentReportChallenge(agentSessionId, nonce.ToArray(), expiresAt);
        }
    }

    public AgentReportDecision Submit(AgentIntegrityReport report, DateTimeOffset now)
    {
        if (!_sessions.TryGetValue(report.AgentSessionId, out State? state))
            return AgentReportDecision.BindingMismatch;
        lock (state.Gate)
        {
            if (state.RevokedAt is not null || state.Session.ExpiresAt <= now)
                return AgentReportDecision.Expired;
            if (state.Challenge is null || state.ChallengeExpiresAt <= now)
                return AgentReportDecision.BindingMismatch;
            AgentReportDecision decision = verifier.Verify(report, state.Session, state.Challenge, now);
            if (decision != AgentReportDecision.Accepted) return decision;
            state.Session = state.Session with
            {
                LastSequence = report.Sequence,
                LastReportDigest = AgentReportCodec.Digest(report)
            };
            state.LastReportAt = now;
            state.Challenge = null;
            state.ChallengeExpiresAt = null;
            return AgentReportDecision.Accepted;
        }
    }

    public AgentSessionHealth Health(string agentSessionId, DateTimeOffset now)
    {
        if (!_sessions.TryGetValue(agentSessionId, out State? state))
            return new(agentSessionId, "missing", null, ["AGENT_SESSION_MISSING"]);
        lock (state.Gate)
        {
            if (state.RevokedAt is not null)
                return new(agentSessionId, "revoked", state.LastReportAt, ["AGENT_SESSION_REVOKED"]);
            if (state.Session.ExpiresAt <= now)
                return new(agentSessionId, "expired", state.LastReportAt, ["AGENT_SESSION_EXPIRED"]);
            if (state.LastReportAt is null || now - state.LastReportAt > TimeSpan.FromMinutes(2))
                return new(agentSessionId, "degraded", state.LastReportAt, ["AGENT_REPORT_STALE"]);
            return new(agentSessionId, "healthy", state.LastReportAt, []);
        }
    }

    public bool Revoke(string agentSessionId, string reason, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 512 || reason.Any(char.IsControl))
            throw new ArgumentException("Revocation reason is invalid.", nameof(reason));
        if (!_sessions.TryGetValue(agentSessionId, out State? state)) return false;
        lock (state.Gate)
        {
            if (state.RevokedAt is not null) return false;
            state.RevokedAt = now;
            state.RevocationReason = reason;
            state.Challenge = null;
            state.ChallengeExpiresAt = null;
            return true;
        }
    }

    private sealed class State(VerifiedAgentSession session)
    {
        internal object Gate { get; } = new();
        internal VerifiedAgentSession Session { get; set; } = session;
        internal byte[]? Challenge { get; set; }
        internal DateTimeOffset? ChallengeExpiresAt { get; set; }
        internal DateTimeOffset? LastReportAt { get; set; }
        internal DateTimeOffset? RevokedAt { get; set; }
        internal string? RevocationReason { get; set; }
    }
}

