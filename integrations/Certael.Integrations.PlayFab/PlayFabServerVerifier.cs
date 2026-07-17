using Certael.Server.Integrations;
namespace Certael.Integrations.PlayFab;
public sealed record PlayFabServerResult(bool Authorized, string ServerId, string TitleId, string Region);
public interface IPlayFabServerApiClient { ValueTask<PlayFabServerResult> VerifyServerAsync(string titleId, string credential, CancellationToken cancellationToken); }
public sealed class PlayFabServerVerifier(IPlayFabServerApiClient client, TimeProvider clock) : IServerIdentityVerifier
{
    public string Provider => "playfab";
    public async ValueTask<AuthoritativeServerIdentity> VerifyAsync(string applicationId, string serverCredential, CancellationToken cancellationToken = default)
    {
        PlayFabServerResult result = await client.VerifyServerAsync(applicationId, serverCredential, cancellationToken);
        if (!result.Authorized || result.TitleId != applicationId) throw new IntegrationException("PLAYFAB_SERVER_REJECTED", "PlayFab rejected the server.");
        return new(Provider, result.ServerId, result.TitleId, result.Region, clock.GetUtcNow());
    }
}
