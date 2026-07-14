namespace Certael.Server.Agent;

public sealed record AgentSessionAdmission(
    VerifiedAgentSession Session, byte[] Challenge, DateTimeOffset ChallengeExpiresAt);

public sealed record AgentStoredHealth(
    string AgentSessionId, string EnvironmentId, string AuthoritativeServerId,
    DateTimeOffset ExpiresAt, DateTimeOffset? LastReportAt, DateTimeOffset? RevokedAt);

public sealed record AgentPlayerDeletionResult(int SessionsDeleted, int RawReportsDeleted);

public interface IAgentSessionStore
{
    ValueTask CreateAsync(VerifiedAgentSession session, CancellationToken cancellationToken);
    ValueTask<VerifiedAgentSession?> FindAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken);
    ValueTask<AgentSessionAdmission?> FindAdmissionAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken);
    ValueTask<AgentStoredHealth?> HealthAsync(string tenantId, string agentSessionId,
        CancellationToken cancellationToken);
    ValueTask<bool> SetChallengeAsync(string tenantId, string agentSessionId,
        byte[] challenge, DateTimeOffset expiresAt, CancellationToken cancellationToken);
    ValueTask<bool> CommitReportAsync(string tenantId, AgentIntegrityReport report,
        byte[] canonicalReport, byte[] reportDigest, DateTimeOffset acceptedAt,
        CancellationToken cancellationToken);
    ValueTask<bool> RevokeAsync(string tenantId, string agentSessionId, string reason,
        DateTimeOffset revokedAt, CancellationToken cancellationToken);
    ValueTask<AgentPlayerDeletionResult> DeletePlayerAsync(string tenantId,
        string environmentId, string playerSubject, CancellationToken cancellationToken);
}
