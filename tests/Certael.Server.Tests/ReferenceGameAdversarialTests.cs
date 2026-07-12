using Certael.ReferenceGame;

namespace Certael.Server.Tests;

public sealed class ReferenceGameAdversarialTests
{
    private static ReferenceGameState State() => new(100,
        new Dictionary<string, long> { ["wood"] = 5 }, 1, DateTimeOffset.UnixEpoch,
        new HashSet<string> { "visible" }, new HashSet<string>());

    [Fact]
    public void ClientCannotForgeEconomyInventoryVisibilityCooldownOrRewards()
    {
        var rules = new ReferenceGameRules(); var state = State();
        Assert.Equal("PRICE_MISMATCH", rules.Purchase(state, "sword", 1, 1,
            new Dictionary<string, long> { ["sword"] = 50 }).PublicReason);
        Assert.Equal("STATE_CHANGED", rules.Purchase(state, "sword", 50, 0,
            new Dictionary<string, long> { ["sword"] = 50 }).PublicReason);
        Assert.Equal("INVALID_QUANTITY", rules.Craft(state, "wood", "plank", -1, 1).PublicReason);
        Assert.Equal("MISSING_INGREDIENTS", rules.Craft(state, "wood", "plank", 6, 1).PublicReason);
        Assert.False(rules.Target(state, "hidden").Passed);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        ReferenceDecision first = rules.UseAbility(state, now, TimeSpan.FromSeconds(5));
        Assert.True(first.Allowed);
        Assert.Equal("ABILITY_COOLDOWN", rules.UseAbility(first.State, now.AddSeconds(1),
            TimeSpan.FromSeconds(5)).PublicReason);
        ReferenceDecision reward = rules.ClaimReward(state, "match-1", 10);
        Assert.True(reward.Allowed);
        Assert.Equal("REWARD_ALREADY_CLAIMED", rules.ClaimReward(reward.State, "match-1", 10).PublicReason);
    }
}
