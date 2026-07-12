using System.Collections.Immutable;
using Certael.Server.Actions;
using Certael.Server.Rules;

namespace Certael.Server.Protections;

public sealed record MovementState(
    double X, double Y, double Z, double VelocityX, double VelocityY, double VelocityZ,
    DateTimeOffset ServerTime, ulong Revision);

public sealed record MovementIntent(
    double X, double Y, double Z, DateTimeOffset ClientTime, ulong ExpectedRevision);

public sealed record MovementPolicy(
    double MaximumSpeed, double MaximumAcceleration, double MaximumStepDistance,
    TimeSpan MaximumServerStep)
{
    public void Validate()
    {
        if (!double.IsFinite(MaximumSpeed) || !double.IsFinite(MaximumAcceleration)
            || !double.IsFinite(MaximumStepDistance) || MaximumSpeed <= 0
            || MaximumAcceleration <= 0 || MaximumStepDistance <= 0
            || MaximumServerStep <= TimeSpan.Zero || MaximumServerStep > TimeSpan.FromSeconds(10))
            throw new ArgumentOutOfRangeException(nameof(MovementPolicy));
    }
}

/// <summary>Checks movement intent using server elapsed time and authoritative state.</summary>
public sealed class AuthoritativeMovementGuard(MovementPolicy policy)
{
    public RuleDecision<MovementState> Evaluate(
        Guid actionId, MovementIntent intent, MovementState current,
        DateTimeOffset serverNow, Func<MovementState, MovementIntent, bool> pathIsAllowed)
    {
        policy.Validate();
        ArgumentNullException.ThrowIfNull(pathIsAllowed);
        if (!Finite(intent.X, intent.Y, intent.Z)) return Reject("INVALID_COORDINATES");
        if (intent.ExpectedRevision != current.Revision) return Reject("STATE_CHANGED");
        double elapsed = (serverNow - current.ServerTime).TotalSeconds;
        if (elapsed <= 0 || elapsed > policy.MaximumServerStep.TotalSeconds)
            return Reject("INVALID_MOVEMENT_WINDOW");

        double dx = intent.X - current.X, dy = intent.Y - current.Y, dz = intent.Z - current.Z;
        double distance = Magnitude(dx, dy, dz);
        if (distance > policy.MaximumStepDistance) return Reject("MOVEMENT_STEP_EXCEEDED");
        double vx = dx / elapsed, vy = dy / elapsed, vz = dz / elapsed;
        if (Magnitude(vx, vy, vz) > policy.MaximumSpeed) return Reject("MOVEMENT_SPEED_EXCEEDED");
        if (Magnitude(vx - current.VelocityX, vy - current.VelocityY, vz - current.VelocityZ) / elapsed
            > policy.MaximumAcceleration) return Reject("MOVEMENT_ACCELERATION_EXCEEDED");
        if (!pathIsAllowed(current, intent)) return Reject("MOVEMENT_PATH_BLOCKED");

        var next = new MovementState(intent.X, intent.Y, intent.Z, vx, vy, vz, serverNow,
            checked(current.Revision + 1));
        return RuleDecision<MovementState>.Accept(next,
            new AuthoritativeEvent(Guid.NewGuid(), actionId, "movement.accepted", 1,
                ReadOnlyMemory<byte>.Empty, serverNow));
    }

    private static RuleDecision<MovementState> Reject(string reason) =>
        RuleDecision<MovementState>.Reject(reason,
            new EvidenceField("movement_rejection", reason, Provenance.AuthoritativeState));
    private static bool Finite(params double[] values) => values.All(double.IsFinite);
    private static double Magnitude(double x, double y, double z) => Math.Sqrt(x * x + y * y + z * z);
}

public sealed record EconomyState(long Balance, ulong Revision);
public sealed record EconomyIntent(long Amount, ulong ExpectedRevision);

public static class AuthoritativeEconomyGuard
{
    public static RuleResult ValidateDebit(EconomyIntent intent, EconomyState state,
        long maximumTransaction)
    {
        if (maximumTransaction <= 0) throw new ArgumentOutOfRangeException(nameof(maximumTransaction));
        if (intent.Amount <= 0 || intent.Amount > maximumTransaction)
            return RuleResult.Fail("INVALID_AMOUNT", 70);
        if (intent.ExpectedRevision != state.Revision) return RuleResult.Fail("STATE_CHANGED", 30);
        if (state.Balance < intent.Amount) return RuleResult.Fail("INSUFFICIENT_FUNDS", 80);
        try { _ = checked(state.Balance - intent.Amount); }
        catch (OverflowException) { return RuleResult.Fail("INVALID_AMOUNT", 100); }
        return RuleResult.Pass();
    }
}

/// <summary>Rejects targeting data the authoritative server did not expose to this player.</summary>
public sealed class AuthoritativeVisibilityGuard
{
    public RuleResult CanTarget(string targetId, IReadOnlySet<string> visibleEntityIds)
    {
        if (string.IsNullOrWhiteSpace(targetId) || targetId.Length > 128)
            return RuleResult.Fail("INVALID_TARGET", 40);
        return visibleEntityIds.Contains(targetId)
            ? RuleResult.Pass()
            : RuleResult.Fail("TARGET_NOT_VISIBLE", 80);
    }

    public static IReadOnlyCollection<T> FilterSnapshot<T>(IEnumerable<T> entities,
        Func<T, bool> serverVisibilityPredicate) => entities.Where(serverVisibilityPredicate).ToArray();
}

public sealed record ServerInputObservation(
    DateTimeOffset ServerTime, double ViewYaw, double ViewPitch, bool PerformedAction,
    DateTimeOffset? TargetBecameActionableAt = null,
    double? PositionX = null, double? PositionY = null, double? PositionZ = null,
    double? NetworkRoundTripMilliseconds = null, string? InputDevice = null);

public sealed record BehavioralFinding(
    string Reason, int RiskContribution, double Confidence,
    string RuleVersion = "1.0.0", IReadOnlyDictionary<string, string>? Features = null);

/// <summary>Produces advisory findings from server-observed input timing; never authorizes a ban.</summary>
public sealed class BehavioralAnalyzer
{
    public IReadOnlyList<BehavioralFinding> Analyze(IReadOnlyList<ServerInputObservation> samples)
    {
        if (samples.Count < 8) return [];
        var findings = new List<BehavioralFinding>();
        if (samples.Any(sample => !double.IsFinite(sample.ViewYaw)
            || !double.IsFinite(sample.ViewPitch)
            || sample.NetworkRoundTripMilliseconds is { } rtt && (!double.IsFinite(rtt) || rtt < 0)
            || sample.PositionX is { } x && !double.IsFinite(x)
            || sample.PositionY is { } y && !double.IsFinite(y)
            || sample.PositionZ is { } z && !double.IsFinite(z)))
            return [new("INVALID_BEHAVIOR_WINDOW", 10, 1,
                Features: new Dictionary<string, string> { ["sample_count"] = samples.Count.ToString() })];
        double[] intervals = samples.Zip(samples.Skip(1),
            (a, b) => (b.ServerTime - a.ServerTime).TotalMilliseconds).ToArray();
        if (intervals.Any(value => value <= 0))
            findings.Add(new("NON_MONOTONIC_INPUT", 15, 0.8,
                Features: Features(("interval_count", intervals.Length))));
        double mean = intervals.Average();
        double variance = intervals.Average(value => Math.Pow(value - mean, 2));
        if (mean > 0 && Math.Sqrt(variance) < 0.25 && samples.Count(value => value.PerformedAction) >= 4)
            findings.Add(new("IMPROBABLY_REGULAR_INPUT", 20, 0.65,
                Features: Features(("interval_stddev_millis", Math.Sqrt(variance)),
                    ("mean_interval_millis", mean))));

        int snaps = 0;
        for (int index = 1; index < samples.Count; index++)
        {
            double milliseconds = intervals[index - 1];
            if (milliseconds <= 0 || milliseconds > 100) continue;
            double yaw = AngularDistance(samples[index - 1].ViewYaw, samples[index].ViewYaw);
            double pitch = Math.Abs(samples[index].ViewPitch - samples[index - 1].ViewPitch);
            if (Math.Sqrt(yaw * yaw + pitch * pitch) >= 45 && samples[index].PerformedAction) snaps++;
        }
        if (snaps >= 3) findings.Add(new("REPEATED_RAPID_VIEW_SNAP", 25, 0.7,
            Features: Features(("rapid_snap_count", snaps))));

        double[] velocities = new double[samples.Count - 1];
        for (int index = 1; index < samples.Count; index++)
        {
            double seconds = intervals[index - 1] / 1000;
            if (seconds <= 0) continue;
            double yaw = AngularDistance(samples[index - 1].ViewYaw, samples[index].ViewYaw);
            double pitch = Math.Abs(samples[index].ViewPitch - samples[index - 1].ViewPitch);
            velocities[index - 1] = Math.Sqrt(yaw * yaw + pitch * pitch) / seconds;
        }
        int extremeAccelerations = 0;
        for (int index = 1; index < velocities.Length; index++)
        {
            double seconds = intervals[index] / 1000;
            if (seconds > 0 && Math.Abs(velocities[index] - velocities[index - 1]) / seconds > 50_000)
                extremeAccelerations++;
        }
        if (extremeAccelerations >= 3)
            findings.Add(new("REPEATED_EXTREME_VIEW_ACCELERATION", 20, 0.6,
                Features: Features(("extreme_acceleration_count", extremeAccelerations))));

        double[] reactionTimes = samples.Where(sample => sample.PerformedAction
                && sample.TargetBecameActionableAt is not null
                && sample.NetworkRoundTripMilliseconds.GetValueOrDefault() < 200)
            .Select(sample => (sample.ServerTime - sample.TargetBecameActionableAt!.Value).TotalMilliseconds)
            .Where(value => value >= 0).ToArray();
        int impossibleReactions = reactionTimes.Count(value => value < 50);
        if (impossibleReactions >= 3)
            findings.Add(new("REPEATED_IMPOSSIBLE_REACTION_WINDOW", 25, 0.75,
                Features: Features(("reaction_count", impossibleReactions),
                    ("minimum_reaction_millis", reactionTimes.Min()))));

        var steps = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int index = 1; index < samples.Count; index++)
        {
            ServerInputObservation prior = samples[index - 1], current = samples[index];
            if (prior.PositionX is null || prior.PositionY is null || prior.PositionZ is null
                || current.PositionX is null || current.PositionY is null || current.PositionZ is null)
                continue;
            string step = FormattableString.Invariant(
                $"{current.PositionX - prior.PositionX:0.000}|{current.PositionY - prior.PositionY:0.000}|{current.PositionZ - prior.PositionZ:0.000}");
            steps[step] = steps.GetValueOrDefault(step) + 1;
        }
        int repeatedSteps = steps.Count == 0 ? 0 : steps.Values.Max();
        if (repeatedSteps >= 8)
            findings.Add(new("REPEATED_IDENTICAL_PATH_STEPS", 15, 0.55,
                Features: Features(("repeated_step_count", repeatedSteps))));
        return findings;
    }

    private static IReadOnlyDictionary<string, string> Features(
        params (string Name, double Value)[] values) => values.ToDictionary(
            value => value.Name,
            value => value.Value.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
            StringComparer.Ordinal);

    private static double AngularDistance(double left, double right)
    {
        double value = Math.Abs((right - left) % 360);
        return value > 180 ? 360 - value : value;
    }
}
