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
        IntegrationValidation.ValidateAssertion(assertion, Provider, clock.GetUtcNow());
        SteamAuthenticationResult result;
        try { result = await client.AuthenticateUserTicketAsync(
            assertion.ApplicationId, assertion.OpaqueAssertion.ToArray(), cancellationToken); }
        catch (Exception exception) when (exception is not (OperationCanceledException
            or IntegrationException))
        { throw new IntegrationException("STEAM_UNAVAILABLE",
            "Steam identity verification is unavailable."); }
        if (!result.Authenticated || result.ApplicationId != assertion.ApplicationId)
            throw new IntegrationException("STEAM_IDENTITY_REJECTED", "Steam rejected the identity assertion.");
        return IntegrationValidation.Verified(Provider, result.SteamId, result.ApplicationId,
            result.AuthoritativeResponse, clock.GetUtcNow());
    }
    public async ValueTask<NormalizedPlatformProof> VerifyIdentityAsync(PlatformProofRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.Provider != Provider || request.Nonce is null or { Length: not 32 }
            || request.Assertion is null or { Length: < 1 or > 1024 * 1024 }
            || !IntegrationValidation.Identifier(request.ExpectedSubject)
            || !IntegrationValidation.Identifier(request.ApplicationId)
            || request.IssuedAt > clock.GetUtcNow()
            || clock.GetUtcNow() - request.IssuedAt > TimeSpan.FromMinutes(5))
            throw new IntegrationException("INVALID_STEAM_PROOF",
                "Steam identity proof request is invalid.");
        VerifiedPlayerIdentity identity = await VerifyAsync(new ExternalIdentityAssertion(Provider,
            request.ApplicationId, request.Assertion, clock.GetUtcNow().AddMinutes(5)), cancellationToken);
        if (identity.Subject != request.ExpectedSubject)
            throw new IntegrationException("STEAM_SUBJECT_MISMATCH", "Steam subject does not match.");
        return new(PlatformProofKind.Identity, Provider, identity.Subject, identity.ApplicationId,
            request.IssuedAt, identity.VerifiedAt, [],
            identity.ClaimsDigest, PlatformProofTrust.Verified, "VERIFIED_IDENTITY");
    }
}
