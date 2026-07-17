using Certael.Server.Integrations;
namespace Certael.Integrations.Agones;
public sealed record AgonesAllocation(bool Ready, string GameServerName, string Fleet, string Region, string TokenAudience);
public interface IAgonesSdkClient { ValueTask<AgonesAllocation> GetAllocationAsync(string credential, CancellationToken cancellationToken); }
public sealed class AgonesServerVerifier(IAgonesSdkClient client, TimeProvider clock) : IServerIdentityVerifier
{
    public string Provider => "agones";
    public async ValueTask<AuthoritativeServerIdentity> VerifyAsync(string applicationId, string serverCredential, CancellationToken cancellationToken = default)
    {
        AgonesAllocation result = await client.GetAllocationAsync(serverCredential, cancellationToken);
        if (!result.Ready || result.TokenAudience != applicationId) throw new IntegrationException("AGONES_SERVER_REJECTED", "Agones allocation is not authoritative for this game.");
        return new(Provider, result.GameServerName, applicationId, result.Region, clock.GetUtcNow());
    }
}
