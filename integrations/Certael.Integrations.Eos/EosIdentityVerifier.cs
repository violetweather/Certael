using Certael.Server.Integrations;
namespace Certael.Integrations.Eos;
public sealed record EosAuthenticationResult(bool Authenticated, string ProductUserId, string ProductId, byte[] AuthoritativeResponse);
public interface IEosConnectClient { ValueTask<EosAuthenticationResult> VerifyIdTokenAsync(string productId, byte[] token, CancellationToken cancellationToken); }
public sealed class EosIdentityVerifier(IEosConnectClient client, TimeProvider clock) : IPlayerIdentityVerifier
{
    public string Provider => "eos";
    public async ValueTask<VerifiedPlayerIdentity> VerifyAsync(ExternalIdentityAssertion assertion, CancellationToken cancellationToken = default)
    {
        if (assertion.Provider != Provider || assertion.ExpiresAt <= clock.GetUtcNow()) throw new IntegrationException("INVALID_EOS_TOKEN", "EOS token is expired or misclassified.");
        EosAuthenticationResult result = await client.VerifyIdTokenAsync(assertion.ApplicationId, assertion.OpaqueAssertion, cancellationToken);
        if (!result.Authenticated || result.ProductId != assertion.ApplicationId) throw new IntegrationException("EOS_IDENTITY_REJECTED", "EOS rejected the identity assertion.");
        return IntegrationValidation.Verified(Provider, result.ProductUserId, result.ProductId, result.AuthoritativeResponse, clock.GetUtcNow());
    }
}
