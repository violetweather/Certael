using Certael.Integrations.Steam;
using Certael.Integrations.Eos;
using Certael.Integrations.PlayFab;
using Certael.Integrations.Agones;
using Certael.Server.Integrations;
using Certael.Server.Sessions;
using System.Net;
using System.Security.Cryptography;
using System.Text;

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

    [Fact]
    public async Task AttestationBindsNonceApplicationAndSubjectAndRejectsReplay()
    {
        DateTimeOffset issuedAt = DateTimeOffset.UtcNow;
        var service = new PlatformProofService([], [new AttestationVerifier()],
            new InMemoryPlatformProofReplayStore(TimeProvider.System), TimeProvider.System);
        var policy = new PlatformProofPolicy("vendor", PlatformProofKind.Attestation,
            PlatformProofRequirement.Required, TimeSpan.FromMinutes(5), "application");
        var request = new PlatformProofRequest("vendor", "application", "player", [1, 2, 3],
            RandomNumberGenerator.GetBytes(32), issuedAt);
        PlatformProofEvaluation accepted = await service.VerifyAsync(policy, request,
            TestContext.Current.CancellationToken);
        Assert.True(accepted.RequirementSatisfied);
        Assert.Equal("VERIFIED", accepted.PublicReason);
        PlatformProofEvaluation replay = await service.VerifyAsync(policy, request,
            TestContext.Current.CancellationToken);
        Assert.False(replay.RequirementSatisfied);
        Assert.Equal("PLATFORM_PROOF_REPLAY", replay.PublicReason);
        PlatformProofEvaluation wrongApplication = await service.VerifyAsync(policy,
            request with { ApplicationId = "other" }, TestContext.Current.CancellationToken);
        Assert.Equal("PLATFORM_PROOF_REQUEST_INVALID", wrongApplication.PublicReason);
    }

    [Fact]
    public async Task MissingProviderFollowsRequiredOrOptionalSignedPolicy()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var profile = new PlatformProofPolicyProfile("policy", "1", "tenant", "game", "prod",
            "vendor", PlatformProofKind.Attestation, PlatformProofRequirement.Optional,
            "application", 300, now.AddHours(1));
        SignedPlatformProofPolicy signed = new PlatformProofPolicySigner(key, "key-1").Sign(profile);
        PlatformProofPolicyProfile verified = PlatformProofPolicySigner.Verify(signed,
            new Dictionary<string, System.Security.Cryptography.ECDsa> { ["key-1"] = key }, now);
        var service = new PlatformProofService([], [],
            new InMemoryPlatformProofReplayStore(TimeProvider.System), TimeProvider.System);
        var request = new PlatformProofRequest("vendor", "application", "player", [1],
            new byte[32], now);
        PlatformProofEvaluation optional = await service.VerifyAsync(
            PlatformProofPolicySigner.ToPolicy(verified), request,
            TestContext.Current.CancellationToken);
        Assert.True(optional.RequirementSatisfied);
        Assert.Equal("OPTIONAL_PROOF_UNAVAILABLE", optional.PublicReason);
        PlatformProofEvaluation required = await service.VerifyAsync(
            PlatformProofPolicySigner.ToPolicy(verified with
            { Requirement = PlatformProofRequirement.Required }), request,
            TestContext.Current.CancellationToken);
        Assert.False(required.RequirementSatisfied);
        Assert.Equal("PLATFORM_PROOF_REQUIRED", required.PublicReason);
    }

    [Fact]
    public async Task SteamWebApiClientUsesOfficialTicketEndpointAndBoundsResponse()
    {
        var handler = new RecordingHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"response\":{\"params\":{\"result\":\"OK\",\"steamid\":\"76561198000000000\"}}}",
                Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var client = new SteamWebApiClient(http, "publisher-web-api-key");
        SteamAuthenticationResult result = await client.AuthenticateUserTicketAsync("480",
            [0xab, 0xcd], TestContext.Current.CancellationToken);
        Assert.True(result.Authenticated);
        Assert.Equal("76561198000000000", result.SteamId);
        Assert.Contains("ISteamUserAuth/AuthenticateUserTicket/v1/", handler.RequestUri!.AbsoluteUri);
        Assert.Contains("appid=480", handler.RequestUri.Query);
        Assert.Contains("ticket=abcd", handler.RequestUri.Query);
    }

    [Fact]
    public async Task EosIdentityIsClassifiedAsIdentityAndBindsAuthoritativeClaims()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var verifier = new EosIdentityVerifier(new EosClient(), TimeProvider.System);
        NormalizedPlatformProof proof = await verifier.VerifyIdentityAsync(
            new PlatformProofRequest("eos", "product", "puid-1", [1, 2], new byte[32], now),
            TestContext.Current.CancellationToken);
        Assert.Equal(PlatformProofKind.Identity, proof.Kind);
        Assert.Equal("puid-1", proof.Subject);
        Assert.Equal(32, proof.ClaimsDigest.Length);
    }

    [Fact]
    public async Task ServerProvidersRejectWrongApplicationAndBoundVendorOutages()
    {
        var playFab = new PlayFabServerVerifier(new PlayFabClient(), TimeProvider.System);
        IntegrationException rejected = await Assert.ThrowsAsync<IntegrationException>(async () =>
            await playFab.VerifyAsync("expected-title", "credential",
                TestContext.Current.CancellationToken));
        Assert.Equal("PLAYFAB_SERVER_REJECTED", rejected.PublicReason);

        var agones = new AgonesServerVerifier(new FailingAgonesClient(), TimeProvider.System);
        IntegrationException unavailable = await Assert.ThrowsAsync<IntegrationException>(async () =>
            await agones.VerifyAsync("game", "allocation-token",
                TestContext.Current.CancellationToken));
        Assert.Equal("AGONES_UNAVAILABLE", unavailable.PublicReason);
        Assert.DoesNotContain("sensitive", unavailable.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BackendLifecycleBindsVerifiedContextStartsAgentAndRevokesCleanly()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var binder = new SessionBinder(now);
        var agent = new AgentLifecycle();
        var integration = new GameBackendSessionIntegration(
            new PlayerVerifier(now), new ServerVerifier(now), binder, agent,
            TimeProvider.System);
        GameBackendSessionRequest request = Request(now);

        GameBackendSession session = await integration.StartAsync(request,
            TestContext.Current.CancellationToken);

        Assert.True(agent.Started);
        Assert.Equal(request.TenantId, session.TenantId);
        Assert.Equal("player-1", session.Session.PlayerSubject);
        Assert.Equal("server-1", session.Session.ServerId);
        Assert.Equal(request.MatchId, session.Session.MatchId);

        await integration.StopAsync(session, "match-complete",
            TestContext.Current.CancellationToken);
        Assert.True(agent.Stopped);
        Assert.Equal((request.TenantId, session.Session.SessionId, "match-complete"),
            Assert.Single(binder.Revocations));
    }

    [Fact]
    public async Task BackendLifecycleRollsBackBoundSessionWhenAgentLaunchFails()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var binder = new SessionBinder(now);
        var agent = new AgentLifecycle { FailStart = true };
        var integration = new GameBackendSessionIntegration(
            new PlayerVerifier(now), new ServerVerifier(now), binder, agent,
            TimeProvider.System);

        IntegrationException failure = await Assert.ThrowsAsync<IntegrationException>(async () =>
            await integration.StartAsync(Request(now), TestContext.Current.CancellationToken));

        Assert.Equal("AGENT_LAUNCH_FAILED", failure.PublicReason);
        Assert.Equal("agent-launch-failed", Assert.Single(binder.Revocations).Reason);
        Assert.True(agent.Stopped);
    }

    [Fact]
    public async Task BackendLifecycleRejectsAndRevokesMisboundCoreSession()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var binder = new SessionBinder(now) { ReturnedPlayer = "different-player" };
        var integration = new GameBackendSessionIntegration(
            new PlayerVerifier(now), new ServerVerifier(now), binder, new AgentLifecycle(),
            TimeProvider.System);

        IntegrationException failure = await Assert.ThrowsAsync<IntegrationException>(async () =>
            await integration.StartAsync(Request(now), TestContext.Current.CancellationToken));

        Assert.Equal("SESSION_BINDING_MISMATCH", failure.PublicReason);
        Assert.Single(binder.Revocations);
    }

    private sealed class SteamClient : ISteamWebApiClient
    {
        public bool Called { get; private set; }
        public ValueTask<SteamAuthenticationResult> AuthenticateUserTicketAsync(string applicationId,
            byte[] ticket, CancellationToken cancellationToken)
        { Called = true; return ValueTask.FromResult(new SteamAuthenticationResult(true, "steam-user", applicationId, [9,8,7])); }
    }

    private sealed class EosClient : IEosConnectClient
    {
        public ValueTask<EosAuthenticationResult> VerifyIdTokenAsync(string productId,
            byte[] token, CancellationToken cancellationToken) => ValueTask.FromResult(
                new EosAuthenticationResult(true, "puid-1", productId, [9, 8, 7]));
    }

    private sealed class AttestationVerifier :
        Certael.Server.Integrations.IPlatformAttestationVerifier
    {
        public string Provider => "vendor";
        public ValueTask<NormalizedPlatformProof> VerifyAttestationAsync(
            PlatformProofRequest request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new NormalizedPlatformProof(
                PlatformProofKind.Attestation, Provider, request.ExpectedSubject,
                request.ApplicationId, request.IssuedAt, DateTimeOffset.UtcNow,
                System.Security.Cryptography.SHA256.HashData(request.Nonce),
                System.Security.Cryptography.SHA256.HashData(request.Assertion),
                PlatformProofTrust.Verified, "VERIFIED_ATTESTATION"));
        }
    }

    private sealed class PlayFabClient : IPlayFabServerApiClient
    {
        public ValueTask<PlayFabServerResult> VerifyServerAsync(string titleId,
            string credential, CancellationToken cancellationToken) => ValueTask.FromResult(
                new PlayFabServerResult(true, "server-1", "different-title", "us-central"));
    }

    private sealed class FailingAgonesClient : IAgonesSdkClient
    {
        public ValueTask<AgonesAllocation> GetAllocationAsync(string credential,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<AgonesAllocation>(
                new InvalidOperationException("sensitive vendor detail"));
    }

    private static GameBackendSessionRequest Request(DateTimeOffset now) => new(
        new ExternalIdentityAssertion("player-provider", "player-app", [1, 2, 3],
            now.AddMinutes(5)), "server-app", "server-credential", "tenant", "game",
        "prod", "match", new byte[32]);

    private sealed class PlayerVerifier(DateTimeOffset now) : IPlayerIdentityVerifier
    {
        public string Provider => "player-provider";
        public ValueTask<VerifiedPlayerIdentity> VerifyAsync(ExternalIdentityAssertion assertion,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(
                new VerifiedPlayerIdentity(Provider, "player-1", assertion.ApplicationId,
                    now, new byte[32]));
    }

    private sealed class ServerVerifier(DateTimeOffset now) : IServerIdentityVerifier
    {
        public string Provider => "server-provider";
        public ValueTask<AuthoritativeServerIdentity> VerifyAsync(string applicationId,
            string serverCredential, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new AuthoritativeServerIdentity(Provider, "server-1",
                applicationId, "us-central", now));
    }

    private sealed class SessionBinder(DateTimeOffset now) : IExternalSessionBinder
    {
        public string ReturnedPlayer { get; init; } = "player-1";
        public List<(string Tenant, string Session, string Reason)> Revocations { get; } = [];
        public ValueTask<BoundExternalSession> BindAsync(SessionBindingRequest request,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(
                new BoundExternalSession("session-1", ReturnedPlayer, request.Server.ServerId,
                    request.MatchId, now.AddMinutes(30)));
        public ValueTask RevokeAsync(string tenantId, string sessionId, string reason,
            CancellationToken cancellationToken = default)
        { Revocations.Add((tenantId, sessionId, reason)); return ValueTask.CompletedTask; }
    }

    private sealed class AgentLifecycle : IAgentLifecycleIntegration
    {
        public bool FailStart { get; init; }
        public bool Started { get; private set; }
        public bool Stopped { get; private set; }
        public ValueTask StartAsync(BoundExternalSession session,
            CancellationToken cancellationToken = default)
        {
            if (FailStart) throw new InvalidOperationException("private vendor failure");
            Started = true; return ValueTask.CompletedTask;
        }
        public ValueTask StopAsync(BoundExternalSession session, string reason,
            CancellationToken cancellationToken = default)
        { Stopped = true; return ValueTask.CompletedTask; }
    }

    private sealed class RecordingHttpHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            return Task.FromResult(response);
        }
    }
}
