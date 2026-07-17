using System.Security.Cryptography;

namespace Certael.Server.Integrations;

public sealed record ExternalIdentityAssertion(string Provider, string ApplicationId,
    byte[] OpaqueAssertion, DateTimeOffset ExpiresAt);
public sealed record VerifiedPlayerIdentity(string Provider, string Subject, string ApplicationId,
    DateTimeOffset VerifiedAt, byte[] ClaimsDigest);
public sealed record AuthoritativeServerIdentity(string Provider, string ServerId, string ApplicationId,
    string Region, DateTimeOffset VerifiedAt);
public sealed record SessionBindingRequest(string TenantId, string GameId, string EnvironmentId,
    VerifiedPlayerIdentity Player, AuthoritativeServerIdentity Server, string MatchId, byte[] ProofKey);
public sealed record BoundExternalSession(string SessionId, string PlayerSubject, string ServerId,
    string MatchId, DateTimeOffset ExpiresAt);

public interface IPlayerIdentityVerifier
{
    string Provider { get; }
    ValueTask<VerifiedPlayerIdentity> VerifyAsync(ExternalIdentityAssertion assertion,
        CancellationToken cancellationToken = default);
}

public interface IServerIdentityVerifier
{
    string Provider { get; }
    ValueTask<AuthoritativeServerIdentity> VerifyAsync(string applicationId, string serverCredential,
        CancellationToken cancellationToken = default);
}

public interface IExternalSessionBinder
{
    ValueTask<BoundExternalSession> BindAsync(SessionBindingRequest request,
        CancellationToken cancellationToken = default);
    ValueTask RevokeAsync(string tenantId, string sessionId, string reason,
        CancellationToken cancellationToken = default);
}

public interface IAgentLifecycleIntegration
{
    ValueTask StartAsync(BoundExternalSession session, CancellationToken cancellationToken = default);
    ValueTask StopAsync(BoundExternalSession session, string reason, CancellationToken cancellationToken = default);
}

public sealed class IntegrationException(string publicReason, string message) : Exception(message)
{
    public string PublicReason { get; } = publicReason;
}

public static class IntegrationValidation
{
    public static VerifiedPlayerIdentity Verified(string provider, string subject, string applicationId,
        ReadOnlySpan<byte> authoritativeClaims, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(subject)
            || string.IsNullOrWhiteSpace(applicationId) || authoritativeClaims.IsEmpty)
            throw new IntegrationException("INVALID_PROVIDER_RESPONSE", "Provider identity response is incomplete.");
        return new VerifiedPlayerIdentity(provider, subject, applicationId, now,
            SHA256.HashData(authoritativeClaims));
    }
}
