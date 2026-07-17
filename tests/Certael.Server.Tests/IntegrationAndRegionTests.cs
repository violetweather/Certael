using Certael.Integrations.Steam;
using Certael.Server.Integrations;
using Certael.Server.Sessions;

namespace Certael.Server.Tests;

public sealed class IntegrationAndRegionTests
{
    [Fact]
    public async Task SteamUsesAuthoritativeBackendResponseAndClassifiesAsIdentity()
    {
        var client = new SteamClient(); var verifier = new SteamIdentityVerifier(client, TimeProvider.System);
        NormalizedPlatformProof proof = await verifier.VerifyIdentityAsync(new PlatformProofRequest(
            "steam", "app", "steam-user", [1,2,3], new byte[32], DateTimeOffset.UtcNow),
            TestContext.Current.CancellationToken);
        Assert.True(client.Called); Assert.Equal(PlatformProofKind.Identity, proof.Kind);
        Assert.Equal(PlatformProofTrust.Verified, proof.Trust);
    }

    [Fact]
    public void RegionTransferGrantIsCanonicalSignedAndExpiresWithinSixtySeconds()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-17T00:00:00Z");
        var grant = new RegionTransferGrantV1(Guid.NewGuid(), "tenant", "game", "prod", "match", "player",
            "us-east", "us-west", 7, new byte[32], now, now.AddSeconds(60));
        SignedRegionTransferGrant signed = new RegionTransferGrantSigner(key, "key-1").Sign(grant);
        RegionTransferGrantV1 verified = RegionTransferGrantSigner.Verify(signed,
            new Dictionary<string, System.Security.Cryptography.ECDsa> { ["key-1"] = key }, now.AddSeconds(1));
        Assert.Equal(grant.GrantId, verified.GrantId);
        Assert.Equal(grant.LeaseEpoch, verified.LeaseEpoch);
        Assert.Equal(grant.Nonce, verified.Nonce);
        Assert.Equal(signed.CanonicalGrant, RegionTransferGrantV1Codec.Encode(verified));
    }

    [Fact]
    public void RequiredAttestationCannotBeSatisfiedByPlatformLogin()
    {
        var policy = new PlatformProofPolicy("steam", PlatformProofKind.Attestation,
            PlatformProofRequirement.Required, TimeSpan.FromMinutes(5));
        var identity = new NormalizedPlatformProof(PlatformProofKind.Identity, "steam", "p", "app",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, new byte[32], new byte[32],
            PlatformProofTrust.Verified, "VERIFIED_IDENTITY");
        Assert.Equal("PLATFORM_PROOF_CLASSIFICATION_MISMATCH",
            PlatformProofPolicyEvaluator.Evaluate(policy, identity, DateTimeOffset.UtcNow));
    }

    private sealed class SteamClient : ISteamWebApiClient
    {
        public bool Called { get; private set; }
        public ValueTask<SteamAuthenticationResult> AuthenticateUserTicketAsync(string applicationId,
            byte[] ticket, CancellationToken cancellationToken)
        { Called = true; return ValueTask.FromResult(new SteamAuthenticationResult(true, "steam-user", applicationId, [9,8,7])); }
    }
}
