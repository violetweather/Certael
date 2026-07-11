using System.Text.Json;
using Certael.Unity;

namespace Certael.Server.Tests;

public sealed class UnityAdapterTests
{
    [Fact]
    public void UnityFacadeCompletesNativeSessionLifecycle()
    {
        using var client = new CertaelClient();
        Assert.Equal(32, client.CreateSessionPublicKey().Length);
        Assert.Equal(64, client.SignRedemption(Guid.NewGuid(), new byte[32]).Length);
        client.ActivateSession("""
            {"session_id":"unity-session","game_id":"game","environment_id":"test","match_id":"match","build_id":"build","expires_at_unix":4102444800}
            """, 4);

        byte[] envelope = client.AuthorizeAction("inventory.craft", 1, [1, 2, 3]);
        using JsonDocument json = JsonDocument.Parse(envelope);
        Assert.Equal("unity-session", json.RootElement.GetProperty("session_id").GetString());
        Assert.Equal(4UL, json.RootElement.GetProperty("sequence").GetUInt64());
        Assert.Equal("inventory.craft", json.RootElement.GetProperty("action_type").GetString());
    }
}
