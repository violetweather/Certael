using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Certael.Server.Sessions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class SessionEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public SessionEndpointTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task HealthIsPublicAndRedemptionIsProofBoundAndSingleUse()
    {
        using HttpClient client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using HttpResponseMessage health = await client.GetAsync("/healthz", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);

        BootstrapTicketSigner signer = _factory.Services.GetRequiredService<BootstrapTicketSigner>();
        using Key ephemeral = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
        byte[] publicKey = ephemeral.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var claims = new BootstrapTicketClaims("https://certael.local", "certael-session", Guid.NewGuid(),
            "tenant", "game", "test", "player", "match", "server", "build", "competitive",
            publicKey, now, now, now.AddSeconds(60), 1, 1);
        SignedBootstrapTicket ticket = signer.Issue(claims, now);
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(ephemeral,
            BootstrapTicketValidator.CreateRedemptionMessage(claims.TicketId, challenge));
        var request = new RedeemTicketRequest(ticket, publicKey, challenge, signature);

        using HttpResponseMessage accepted = await client.PostAsJsonAsync(
            "/v1/sessions/redeem", request, TestContext.Current.CancellationToken);
        using HttpResponseMessage replay = await client.PostAsJsonAsync(
            "/v1/sessions/redeem", request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        ActiveSessionResponse? session = await accepted.Content.ReadFromJsonAsync<ActiveSessionResponse>(
            TestContext.Current.CancellationToken);
        Assert.NotNull(session);
        Assert.Equal("match", session.MatchId);
        Assert.Equal("build", session.BuildId);
    }
}
