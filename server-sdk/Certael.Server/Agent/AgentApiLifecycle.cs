using System.Security.Cryptography;

namespace Certael.Server.Agent;

public sealed record AgentLaunchParameters(
    string TenantId, string GameId, string EnvironmentId, string PlayerSubject,
    string MatchId, string AuthoritativeServerId, string BuildId, byte[] AgentPublicKey,
    AgentPolicyClaims Policy, TimeSpan SessionLifetime);

public sealed record AgentLaunchBundle(
    string AgentSessionId, SignedAgentPolicy Policy, SignedAgentLaunchGrant Grant,
    DateTimeOffset ExpiresAt);

public sealed class AgentApiLifecycle(
    AgentGrantSigner signer,
    AgentReportVerifier verifier,
    IAgentSessionStore store,
    TimeProvider clock,
    IAgentPolicyResolver policies,
    IAgentBuildRegistry builds)
{
    public async ValueTask<AgentLaunchBundle> LaunchAsync(AgentLaunchParameters request,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (!Identifier(request.TenantId) || !Identifier(request.GameId)
            || !Identifier(request.EnvironmentId) || !Identifier(request.PlayerSubject)
            || !Identifier(request.MatchId) || !Identifier(request.AuthoritativeServerId)
            || !Identifier(request.BuildId) || request.AgentPublicKey.Length != 32
            || request.SessionLifetime < TimeSpan.FromMinutes(1)
            || request.SessionLifetime > TimeSpan.FromHours(8)
            || !Identifier(request.Policy.PolicyId))
            throw new ArgumentException("Agent launch request is invalid.");

        if (!await builds.IsApprovedAsync(request.TenantId, request.GameId,
            request.EnvironmentId, request.BuildId, cancellationToken))
            throw new AgentBuildRegistryException("Agent build is not approved.");
        AgentPolicyDeployment approved = await policies.ResolveAsync(request.Policy.PolicyId,
            request.TenantId, request.GameId, request.EnvironmentId,
            $"{request.PlayerSubject}\0{request.MatchId}", now, cancellationToken);
        SignedAgentPolicy policy = approved.SignedPolicy;
        string sessionId = Guid.NewGuid().ToString("N");
        DateTimeOffset grantExpiresAt = now.AddSeconds(60);
        var grantClaims = new AgentLaunchGrantClaims(1, sessionId, request.TenantId,
            request.GameId, request.EnvironmentId, request.PlayerSubject, request.MatchId,
            request.BuildId, request.AgentPublicKey.ToArray(), now, grantExpiresAt,
            AgentGrantCodec.PolicyDigest(policy), request.AuthoritativeServerId);
        SignedAgentLaunchGrant grant = signer.IssueLaunchGrant(grantClaims, now);
        DateTimeOffset sessionExpiresAt = now.Add(request.SessionLifetime);
        await store.CreateAsync(new VerifiedAgentSession(sessionId, request.TenantId,
            request.GameId, request.EnvironmentId, request.PlayerSubject, request.MatchId,
            request.BuildId, request.AgentPublicKey.ToArray(), 0, new byte[32],
            sessionExpiresAt, request.AuthoritativeServerId), cancellationToken);
        return new(sessionId, policy, grant, sessionExpiresAt);
    }

    public async ValueTask<AgentReportChallenge?> ChallengeAsync(string tenantId,
        string environmentId, string authoritativeServerId, string agentSessionId,
        CancellationToken cancellationToken)
    {
        VerifiedAgentSession? session = await store.FindAsync(tenantId, agentSessionId,
            cancellationToken);
        DateTimeOffset now = clock.GetUtcNow();
        if (!Bound(session, environmentId, authoritativeServerId) || session!.ExpiresAt <= now)
            return null;
        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        DateTimeOffset expiresAt = now.AddSeconds(30);
        return await store.SetChallengeAsync(tenantId, agentSessionId, nonce, expiresAt,
            cancellationToken) ? new(agentSessionId, nonce, expiresAt) : null;
    }

    public async ValueTask<AgentReportDecision> SubmitAsync(string tenantId,
        string environmentId, string authoritativeServerId, AgentIntegrityReport report,
        CancellationToken cancellationToken)
    {
        AgentSessionAdmission? admission = await store.FindAdmissionAsync(tenantId,
            report.AgentSessionId, cancellationToken);
        DateTimeOffset now = clock.GetUtcNow();
        if (admission is null || !Bound(admission.Session, environmentId, authoritativeServerId))
            return AgentReportDecision.BindingMismatch;
        if (admission.ChallengeExpiresAt <= now) return AgentReportDecision.Expired;
        AgentReportDecision decision = verifier.Verify(report, admission.Session,
            admission.Challenge, now);
        if (decision != AgentReportDecision.Accepted) return decision;
        byte[] canonical = AgentReportCodec.Encode(report);
        byte[] digest = AgentReportCodec.Digest(report);
        return await store.CommitReportAsync(tenantId, report, canonical, digest, now,
            cancellationToken) ? AgentReportDecision.Accepted : AgentReportDecision.Replay;
    }

    public async ValueTask<AgentSessionHealth> HealthAsync(string tenantId, string environmentId,
        string authoritativeServerId, string agentSessionId, TimeSpan staleAfter,
        CancellationToken cancellationToken)
    {
        AgentStoredHealth? health = await store.HealthAsync(tenantId, agentSessionId,
            cancellationToken);
        DateTimeOffset now = clock.GetUtcNow();
        if (health is null)
            return new(agentSessionId, "missing", null, ["AGENT_SESSION_MISSING"]);
        if (!string.Equals(health.EnvironmentId, environmentId, StringComparison.Ordinal)
            || !string.Equals(health.AuthoritativeServerId, authoritativeServerId,
                StringComparison.Ordinal))
            return new(agentSessionId, "missing", null, ["AGENT_SESSION_MISSING"]);
        if (health.RevokedAt is not null)
            return new(agentSessionId, "revoked", health.LastReportAt, ["AGENT_SESSION_REVOKED"]);
        if (health.ExpiresAt <= now)
            return new(agentSessionId, "expired", health.LastReportAt, ["AGENT_SESSION_EXPIRED"]);
        if (health.LastReportAt is null || now - health.LastReportAt > staleAfter)
            return new(agentSessionId, "degraded", health.LastReportAt, ["AGENT_REPORT_STALE"]);
        return new(agentSessionId, "healthy", health.LastReportAt, []);
    }

    public async ValueTask<bool> RevokeAsync(string tenantId, string environmentId,
        string authoritativeServerId, string agentSessionId, string reason,
        CancellationToken cancellationToken)
    {
        VerifiedAgentSession? session = await store.FindAsync(tenantId, agentSessionId,
            cancellationToken);
        return Bound(session, environmentId, authoritativeServerId)
            && await store.RevokeAsync(tenantId, agentSessionId, reason, clock.GetUtcNow(),
                cancellationToken);
    }

    private static bool Bound(VerifiedAgentSession? session, string environmentId,
        string authoritativeServerId) => session is not null
        && string.Equals(session.EnvironmentId, environmentId, StringComparison.Ordinal)
        && string.Equals(session.AuthoritativeServerId, authoritativeServerId,
            StringComparison.Ordinal);

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');
}
