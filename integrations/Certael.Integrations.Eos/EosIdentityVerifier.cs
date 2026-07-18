using Certael.Server.Integrations;
namespace Certael.Integrations.Eos;
public sealed record EosAuthenticationResult(bool Authenticated, string ProductUserId, string ProductId, byte[] AuthoritativeResponse);
public interface IEosConnectClient { ValueTask<EosAuthenticationResult> VerifyIdTokenAsync(string productId, byte[] token, CancellationToken cancellationToken); }
public sealed class EosIdentityVerifier(IEosConnectClient client, TimeProvider clock)
    : IPlayerIdentityVerifier, IPlatformIdentityVerifier
{
    public string Provider => "eos";
    public async ValueTask<VerifiedPlayerIdentity> VerifyAsync(ExternalIdentityAssertion assertion, CancellationToken cancellationToken = default)
    {
        IntegrationValidation.ValidateAssertion(assertion, Provider, clock.GetUtcNow());
        EosAuthenticationResult result;
        try { result = await client.VerifyIdTokenAsync(assertion.ApplicationId,
            assertion.OpaqueAssertion.ToArray(), cancellationToken); }
        catch (Exception exception) when (exception is not (OperationCanceledException
            or IntegrationException))
        { throw new IntegrationException("EOS_UNAVAILABLE",
            "EOS identity verification is unavailable."); }
        if (!result.Authenticated || result.ProductId != assertion.ApplicationId) throw new IntegrationException("EOS_IDENTITY_REJECTED", "EOS rejected the identity assertion.");
        return IntegrationValidation.Verified(Provider, result.ProductUserId, result.ProductId, result.AuthoritativeResponse, clock.GetUtcNow());
    }
    public async ValueTask<NormalizedPlatformProof> VerifyIdentityAsync(PlatformProofRequest request,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (request.Provider != Provider || request.Nonce is null or { Length: not 32 }
            || request.Assertion is null or { Length: < 1 or > 1024 * 1024 }
            || !IntegrationValidation.Identifier(request.ExpectedSubject)
            || !IntegrationValidation.Identifier(request.ApplicationId)
            || request.IssuedAt > now || now - request.IssuedAt > TimeSpan.FromMinutes(5))
            throw new IntegrationException("INVALID_EOS_PROOF", "EOS identity proof request is invalid.");
        VerifiedPlayerIdentity identity = await VerifyAsync(new ExternalIdentityAssertion(Provider,
            request.ApplicationId, request.Assertion, now.AddMinutes(5)), cancellationToken);
        if (identity.Subject != request.ExpectedSubject)
            throw new IntegrationException("EOS_SUBJECT_MISMATCH", "EOS subject does not match.");
        return new(PlatformProofKind.Identity, Provider, identity.Subject, identity.ApplicationId,
            request.IssuedAt, identity.VerifiedAt, [], identity.ClaimsDigest,
            PlatformProofTrust.Verified, "VERIFIED_IDENTITY");
    }
}
