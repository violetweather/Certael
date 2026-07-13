namespace Certael.Server.Agent;

public interface IAgentSessionStore
{
    ValueTask CreateAsync(VerifiedAgentSession session, CancellationToken cancellationToken);
    ValueTask<VerifiedAgentSession?> FindAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken);
    ValueTask<bool> SetChallengeAsync(string tenantId, string agentSessionId,
        byte[] challenge, DateTimeOffset expiresAt, CancellationToken cancellationToken);
    ValueTask<bool> CommitReportAsync(string tenantId, AgentIntegrityReport report,
        byte[] canonicalReport, byte[] reportDigest, DateTimeOffset acceptedAt,
        CancellationToken cancellationToken);
    ValueTask<bool> RevokeAsync(string tenantId, string agentSessionId, string reason,
        DateTimeOffset revokedAt, CancellationToken cancellationToken);
}
