using Certael.Server.Rules;

namespace Certael.ReferenceGame;

public sealed record ReferenceGameState(
    long Balance,
    IReadOnlyDictionary<string, long> Inventory,
    ulong Revision,
    DateTimeOffset AbilityReadyAt,
    IReadOnlySet<string> VisibleEntities,
    IReadOnlySet<string> ClaimedRewards);

public sealed record ReferenceDecision(bool Allowed, string PublicReason, ReferenceGameState State)
{
    public static ReferenceDecision Reject(string reason, ReferenceGameState state) => new(false, reason, state);
    public static ReferenceDecision Accept(ReferenceGameState state) => new(true, "ACCEPTED", state);
}

/// <summary>Small authoritative domain used identically by all engine samples.</summary>
public sealed class ReferenceGameRules
{
    public ReferenceDecision Purchase(ReferenceGameState state, string itemId,
        long clientClaimedPrice, ulong expectedRevision, IReadOnlyDictionary<string, long> serverPrices)
    {
        if (expectedRevision != state.Revision) return ReferenceDecision.Reject("STATE_CHANGED", state);
        if (!serverPrices.TryGetValue(itemId, out long price) || price <= 0)
            return ReferenceDecision.Reject("INVALID_ITEM", state);
        if (clientClaimedPrice != price) return ReferenceDecision.Reject("PRICE_MISMATCH", state);
        if (state.Balance < price) return ReferenceDecision.Reject("INSUFFICIENT_FUNDS", state);
        try
        {
            var inventory = new Dictionary<string, long>(state.Inventory, StringComparer.Ordinal);
            inventory[itemId] = checked(inventory.GetValueOrDefault(itemId) + 1);
            return ReferenceDecision.Accept(state with {
                Balance = checked(state.Balance - price), Inventory = inventory,
                Revision = checked(state.Revision + 1)
            });
        }
        catch (OverflowException) { return ReferenceDecision.Reject("NUMERIC_OVERFLOW", state); }
    }

    public ReferenceDecision Craft(ReferenceGameState state, string ingredient, string output,
        long quantity, ulong expectedRevision)
    {
        if (expectedRevision != state.Revision) return ReferenceDecision.Reject("STATE_CHANGED", state);
        if (quantity is < 1 or > 100) return ReferenceDecision.Reject("INVALID_QUANTITY", state);
        if (state.Inventory.GetValueOrDefault(ingredient) < quantity)
            return ReferenceDecision.Reject("MISSING_INGREDIENTS", state);
        try
        {
            var inventory = new Dictionary<string, long>(state.Inventory, StringComparer.Ordinal);
            inventory[ingredient] = checked(inventory[ingredient] - quantity);
            inventory[output] = checked(inventory.GetValueOrDefault(output) + quantity);
            return ReferenceDecision.Accept(state with { Inventory = inventory, Revision = checked(state.Revision + 1) });
        }
        catch (OverflowException) { return ReferenceDecision.Reject("NUMERIC_OVERFLOW", state); }
    }

    public ReferenceDecision UseAbility(ReferenceGameState state, DateTimeOffset serverNow, TimeSpan cooldown)
    {
        if (cooldown <= TimeSpan.Zero || cooldown > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(cooldown));
        if (serverNow < state.AbilityReadyAt) return ReferenceDecision.Reject("ABILITY_COOLDOWN", state);
        return ReferenceDecision.Accept(state with {
            AbilityReadyAt = serverNow + cooldown, Revision = checked(state.Revision + 1)
        });
    }

    public RuleResult Target(ReferenceGameState state, string entityId) =>
        new Certael.Server.Protections.AuthoritativeVisibilityGuard().CanTarget(entityId, state.VisibleEntities);

    public ReferenceDecision ClaimReward(ReferenceGameState state, string rewardId, long amount)
    {
        if (string.IsNullOrWhiteSpace(rewardId) || amount is < 1 or > 1_000_000)
            return ReferenceDecision.Reject("INVALID_REWARD", state);
        if (state.ClaimedRewards.Contains(rewardId)) return ReferenceDecision.Reject("REWARD_ALREADY_CLAIMED", state);
        try
        {
            var claimed = new HashSet<string>(state.ClaimedRewards, StringComparer.Ordinal) { rewardId };
            return ReferenceDecision.Accept(state with {
                Balance = checked(state.Balance + amount), ClaimedRewards = claimed,
                Revision = checked(state.Revision + 1)
            });
        }
        catch (OverflowException) { return ReferenceDecision.Reject("NUMERIC_OVERFLOW", state); }
    }
}
