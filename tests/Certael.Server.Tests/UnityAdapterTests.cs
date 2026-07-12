using Certael.Unity;
using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class UnityAdapterTests
{
    [Fact]
    public void UnityFacadeCompletesNativeSessionLifecycle()
    {
        using var client = new CertaelClient();
        Assert.Equal(32, client.CreateSessionPublicKey().Length);
        Assert.Equal(64, client.SignRedemption(Guid.NewGuid(), new byte[32]).Length);
        client.ActivateSession(new CertaelSessionBinding {
            SessionId = "unity-session", GameId = "game", EnvironmentId = "test",
            MatchId = "match", BuildId = "build", ExpiresAtUnix = 4102444800,
            InitialSequence = 4, BindingDigest = Enumerable.Repeat((byte)7, 32).ToArray()
        });

        byte[] envelope = client.AuthorizeAction("inventory.craft", "example.Craft.v1", 1, [1, 2, 3]);
        AuthorizedAction<byte[]> action = BinaryActionEnvelopeCodec.Decode(envelope, DateTimeOffset.UtcNow);
        Assert.Equal("unity-session", action.SessionId);
        Assert.Equal(4UL, action.Sequence);
        Assert.Equal("inventory.craft", action.ActionType);
    }
}
