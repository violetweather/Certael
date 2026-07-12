using System.Security.Cryptography;
using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class ActionAdmissionTests
{
    [Fact]
    public async Task EnforcesChainReplayAndRateAtomically()
    {
        var store = new InMemoryActionAdmissionStore();
        var policy = new ActionAdmissionPolicy(2, TimeSpan.FromSeconds(10));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        byte[] zero = new byte[32];
        byte[] one = SHA256.HashData("one"u8);
        byte[] two = SHA256.HashData("two"u8);
        byte[] three = SHA256.HashData("three"u8);
        byte[] four = SHA256.HashData("four"u8);
        CancellationToken token = TestContext.Current.CancellationToken;

        Assert.True((await store.TryAdmitAsync(new("s", "move", 1, zero, one, now), policy, token)).Allowed);
        Assert.Equal("ACTION_CHAIN_MISMATCH", (await store.TryAdmitAsync(
            new("s", "move", 2, zero, two, now), policy, token)).PublicReason);
        Assert.True((await store.TryAdmitAsync(new("s", "move", 2, one, two, now), policy, token)).Allowed);
        Assert.Equal("REPLAY_OR_REORDER", (await store.TryAdmitAsync(
            new("s", "move", 2, two, three, now), policy, token)).PublicReason);
        Assert.Equal("ACTION_RATE_LIMITED", (await store.TryAdmitAsync(
            new("s", "move", 3, two, three, now), policy, token)).PublicReason);
        Assert.True((await store.TryAdmitAsync(
            new("s", "move", 4, three, four, now.AddSeconds(11)), policy, token)).Allowed);
    }
}
