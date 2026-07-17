using Certael.Server.Integrations;

namespace Certael.Integrations.Steam;

public sealed record SteamAuthenticationResult(bool Authenticated, string SteamId, string ApplicationId,
    byte[] AuthoritativeResponse);
public interface ISteamWebApiClient
{
    ValueTask<SteamAuthenticationResult> AuthenticateUserTicketAsync(string applicationId,
        byte[] ticket, CancellationToken cancellationToken);
}
public sealed class SteamIdentityVerifier(ISteamWebApiClient client, TimeProvider clock)
    : IPlayerIdentityVerifier, IPlatformIdentityVerifier
{
    public string Provider => "steam";
    public async ValueTask<VerifiedPlayerIdentity> VerifyAsync(ExternalIdentityAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        if (assertion.Provider != Provider || assertion.ExpiresAt <= clock.GetUtcNow())
            throw new IntegrationException("INVALID_STEAM_TICKET", "Steam ticket is expired or misclassified.");
        SteamAuthenticationResult result = await client.AuthenticateUserTicketAsync(
            assertion.ApplicationId, assertion.OpaqueAssertion, cancellationToken);
        if (!result.Authenticated || result.ApplicationId != assertion.ApplicationId)
            throw new IntegrationException("STEAM_IDENTITY_REJECTED", "Steam rejected the identity assertion.");
        return IntegrationValidation.Verified(Provider, result.SteamId, result.ApplicationId,
            result.AuthoritativeResponse, clock.GetUtcNow());
    }
    public async ValueTask<NormalizedPlatformProof> VerifyIdentityAsync(PlatformProofRequest request,
        CancellationToken cancellationToken = default)
    {
        VerifiedPlayerIdentity identity = await VerifyAsync(new ExternalIdentityAssertion(Provider,
            request.ApplicationId, request.Assertion, request.IssuedAt.AddMinutes(5)), cancellationToken);
        if (identity.Subject != request.ExpectedSubject)
            throw new IntegrationException("STEAM_SUBJECT_MISMATCH", "Steam subject does not match.");
        return new(PlatformProofKind.Identity, Provider, identity.Subject, identity.ApplicationId,
            request.IssuedAt, identity.VerifiedAt, System.Security.Cryptography.SHA256.HashData(request.Nonce),
            identity.ClaimsDigest, PlatformProofTrust.Verified, "VERIFIED_IDENTITY");
    }
}
