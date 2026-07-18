using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certael.Server.Actions;
using Certael.Server.Evidence;

namespace Certael.Server.Economy;

public enum EconomyProfileStage { Shadow, Canary, Enforced, RolledBack }

public sealed record EconomyProtectionProfile(
    string ProfileId,
    string Version,
    string TenantId,
    string GameId,
    string EnvironmentId,
    int MaximumTransactionsPerWindow,
    long MaximumProgressionPerWindow,
    int RepeatedRewardLimit,
    TimeSpan Window,
    DateTimeOffset ExpiresAt,
    int FindingRisk = 60,
    int ConfidenceBasisPoints = 9000,
    VerdictRecommendation Recommendation = VerdictRecommendation.RecommendManualReview);

public sealed record SignedEconomyProtectionProfile(
    byte[] CanonicalProfile, byte[] Signature, string KeyId, byte[] Digest);

public sealed record EconomyProfileDeployment(
    SignedEconomyProtectionProfile SignedProfile,
    EconomyProfileStage Stage,
    int CanaryPercentage);

public static class EconomyProfileDeploymentValidation
{
    public static void Validate(EconomyProfileStage stage, int canaryPercentage)
    {
        if (!Enum.IsDefined(stage)
            || stage == EconomyProfileStage.Canary && canaryPercentage is < 1 or > 99
            || stage != EconomyProfileStage.Canary && canaryPercentage != 0)
            throw new EconomyEventException("Economy profile deployment is invalid.");
    }
}

public sealed class EconomyProtectionProfileSigner(ECDsa key, string keyId)
{
    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public SignedEconomyProtectionProfile Sign(EconomyProtectionProfile profile)
    {
        Validate(profile);
        if (!Identifier(keyId) || key.KeySize != 256)
            throw new EconomyEventException("Economy profile signing key is invalid.");
        byte[] canonical = EncodeCanonical(profile);
        byte[] digest = SHA256.HashData(canonical);
        return new SignedEconomyProtectionProfile(canonical,
            key.SignData(canonical, HashAlgorithmName.SHA256), keyId, digest);
    }

    public static EconomyProtectionProfile Verify(SignedEconomyProtectionProfile signed,
        IReadOnlyDictionary<string, ECDsa> keys, DateTimeOffset now)
    {
        if (signed.CanonicalProfile.Length is < 1 or > 64 * 1024
            || signed.Signature.Length is < 64 or > 512 || !Identifier(signed.KeyId)
            || !keys.TryGetValue(signed.KeyId, out ECDsa? key) || key.KeySize != 256
            || signed.Digest.Length != 32
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(signed.CanonicalProfile), signed.Digest)
            || !key.VerifyData(signed.CanonicalProfile, signed.Signature, HashAlgorithmName.SHA256))
            throw new EconomyEventException("Economy profile signature is invalid.");
        EconomyProtectionProfile profile = DecodeCanonical(signed.CanonicalProfile);
        if (profile.ExpiresAt <= now) throw new EconomyEventException("Economy profile is expired.");
        return profile;
    }

    public static byte[] EncodeCanonical(EconomyProtectionProfile profile)
    {
        Validate(profile);
        return JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson);
    }

    public static EconomyProtectionProfile DecodeCanonical(ReadOnlySpan<byte> canonical)
    {
        if (canonical.IsEmpty || canonical.Length > 64 * 1024)
            throw new EconomyEventException("Economy profile size is invalid.");
        EconomyProtectionProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<EconomyProtectionProfile>(canonical, CanonicalJson)
                ?? throw new EconomyEventException("Economy profile is malformed.");
        }
        catch (JsonException exception)
        { throw new EconomyEventException("Economy profile is malformed.", exception); }
        Validate(profile);
        if (!CryptographicOperations.FixedTimeEquals(
                JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson), canonical))
            throw new EconomyEventException("Economy profile encoding is not canonical.");
        return profile;
    }

    private static void Validate(EconomyProtectionProfile profile)
    {
        if (!Identifier(profile.ProfileId) || !Identifier(profile.Version)
            || !Identifier(profile.TenantId) || !Identifier(profile.GameId)
            || !Identifier(profile.EnvironmentId)
            || profile.MaximumTransactionsPerWindow is < 1 or > 1_000_000
            || profile.MaximumProgressionPerWindow < 1 || profile.RepeatedRewardLimit is < 1 or > 100_000
            || profile.Window <= TimeSpan.Zero || profile.Window > TimeSpan.FromDays(90)
            || profile.FindingRisk is < 1 or > 100
            || profile.ConfidenceBasisPoints is < 1 or > 10_000
            || !Enum.IsDefined(profile.Recommendation))
            throw new EconomyEventException("Economy profile is invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
}

public sealed record EconomyFinding(
    string RuleId,
    string RuleVersion,
    string ProfileId,
    string ProfileVersion,
    EconomyProfileStage ProfileStage,
    IReadOnlyList<Guid> EventIds,
    DateTimeOffset WindowStart,
    DateTimeOffset WindowEnd,
    IReadOnlyDictionary<string, string> AuthoritativeFields,
    byte[] ReplayDigest);

public interface IEconomyEventSink
{
    ValueTask StageAsync(EconomyEventV1 value, CancellationToken cancellationToken = default);
}

public sealed class AuthoritativeTransactionEconomyEventSink<TState>(
    IAuthoritativeTransaction<TState> transaction) : IEconomyEventSink
{
    public ValueTask StageAsync(EconomyEventV1 value, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Guid actionId = value.Transaction?.AuthoritativeActionId
            ?? value.ItemMutation?.AuthoritativeActionId
            ?? throw new EconomyEventException("Economy event has no authoritative action.");
        transaction.EnqueueAuthoritativeEvent(new AuthoritativeEvent(
            value.EventId,
            actionId,
            "economy.v1",
            EconomyEventV1Codec.SchemaVersion,
            EconomyEventV1Codec.Encode(value),
            value.OccurredAt));
        return ValueTask.CompletedTask;
    }
}

public static class EconomyProtectionEvaluator
{
    public const string RuleVersion = "1.0.0";

    public static IReadOnlyList<EconomyFinding> Evaluate(
        IEnumerable<EconomyEventV1> source, EconomyProtectionProfile profile,
        EconomyProfileStage stage = EconomyProfileStage.Enforced, int canaryPercentage = 0)
    {
        EconomyProfileDeploymentValidation.Validate(stage, canaryPercentage);
        EconomyEventV1[] ordered = source.OrderBy(value => value.OccurredAt)
            .ThenBy(value => value.EventId).ToArray();
        if (ordered.Length == 0 || stage == EconomyProfileStage.RolledBack) return [];
        if (stage == EconomyProfileStage.Canary)
            ordered = ordered.Where(value => CanarySelected(profile, canaryPercentage,
                value.PlayerSubject)).ToArray();
        if (ordered.Length == 0) return [];
        DateTimeOffset windowEnd = ordered[^1].OccurredAt;
        EconomyEventV1[] events = ordered.Where(value => value.OccurredAt > windowEnd - profile.Window
            && value.OccurredAt <= windowEnd).ToArray();
        if (events.Any(value => value.TenantId != profile.TenantId || value.GameId != profile.GameId
            || value.EnvironmentId != profile.EnvironmentId))
            throw new EconomyEventException("Cross-boundary economy evaluation is prohibited.");
        var findings = new List<EconomyFinding>();
        byte[] digest = EconomyEventV1Codec.ReplayDigest(events);
        DateTimeOffset start = events[0].OccurredAt;
        DateTimeOffset end = events[^1].OccurredAt;

        foreach (IGrouping<string, EconomyEventV1> duplicate in events.Where(e => e.Transaction is not null)
                     .GroupBy(e => e.Transaction!.TransactionId).Where(group => group.Count() > 1))
            Add(findings, profile, stage, "duplicate-transaction", duplicate, start, end, digest,
                new Dictionary<string, string> { ["transactionId"] = duplicate.Key });

        foreach (EconomyEventV1 value in events.Where(e => e.Transaction is not null))
        {
            foreach (IGrouping<string, EconomyLedgerLine> asset in value.Transaction!.Lines.GroupBy(l => l.AssetId))
                if (asset.Sum(line => line.Quantity) != 0)
                    Add(findings, profile, stage, "conservation", [value], start, end, digest,
                        new Dictionary<string, string> { ["assetId"] = asset.Key,
                            ["imbalance"] = asset.Sum(line => line.Quantity).ToString() });
        }

        var created = new HashSet<string>(StringComparer.Ordinal);
        foreach (EconomyEventV1 value in events.Where(e => e.ItemMutation is not null))
        {
            ItemLineageMutation mutation = value.ItemMutation!;
            if (mutation.MutationKind == ItemMutationKind.Create && !created.Add(mutation.ItemId))
                Add(findings, profile, stage, "duplicate-item", [value], start, end, digest,
                    new Dictionary<string, string> { ["itemId"] = mutation.ItemId });
            if (mutation.ParentItemId is not null && !created.Contains(mutation.ParentItemId))
                Add(findings, profile, stage, "broken-lineage", [value], start, end, digest,
                    new Dictionary<string, string> { ["itemId"] = mutation.ItemId,
                        ["parentItemId"] = mutation.ParentItemId });
        }

        foreach (IGrouping<Guid, EconomyEventV1> repeated in events.GroupBy(ActionId)
                     .Where(group => group.Count(value => Reason(value).Contains("reward", StringComparison.OrdinalIgnoreCase))
                         > profile.RepeatedRewardLimit))
            Add(findings, profile, stage, "repeated-reward", repeated, start, end, digest,
                new Dictionary<string, string> { ["authoritativeActionId"] = repeated.Key.ToString() });

        foreach (IGrouping<string, EconomyEventV1> account in events.Where(e => e.Transaction is not null)
                     .GroupBy(e => e.Transaction!.SourceAccountId)
                     .Where(group => group.Count() > profile.MaximumTransactionsPerWindow))
            Add(findings, profile, stage, "suspicious-velocity", account, start, end, digest,
                new Dictionary<string, string> { ["accountId"] = account.Key,
                    ["count"] = account.Count().ToString(), ["window"] = profile.Window.ToString() });

        foreach (IGrouping<string, EconomyLedgerLine> progression in events.Where(e => e.Transaction is not null
                     && Reason(e).Contains("progress", StringComparison.OrdinalIgnoreCase))
                     .SelectMany(e => e.Transaction!.Lines).Where(line => line.Quantity > 0)
                     .GroupBy(line => line.AssetId).Where(group => group.Sum(line => line.Quantity)
                         > profile.MaximumProgressionPerWindow))
            Add(findings, profile, stage, "impossible-progression", events.Where(e => e.Transaction?.Lines
                    .Any(line => line.AssetId == progression.Key && line.Quantity > 0) == true), start, end, digest,
                new Dictionary<string, string> { ["assetId"] = progression.Key,
                    ["quantity"] = progression.Sum(line => line.Quantity).ToString() });

        foreach (EconomyEventV1[] cycle in TransferCycles(events))
            Add(findings, profile, stage, "circular-transfer", cycle, start, end, digest,
                new Dictionary<string, string> { ["edgeCount"] = cycle.Length.ToString() });

        return findings.OrderBy(value => value.RuleId).ThenBy(value => value.EventIds[0]).ToArray();
    }

    public static ValueTask StageAsync<TState>(IAuthoritativeTransaction<TState> transaction,
        EconomyEventV1 value, CancellationToken cancellationToken = default) =>
        new AuthoritativeTransactionEconomyEventSink<TState>(transaction)
            .StageAsync(value, cancellationToken);

    private static IEnumerable<EconomyEventV1[]> TransferCycles(EconomyEventV1[] events)
    {
        EconomyEventV1[] transfers = events.Where(e => e.Transaction is not null).ToArray();
        foreach (EconomyEventV1 first in transfers)
            foreach (EconomyEventV1 second in transfers.Where(e => e.EventId != first.EventId
                         && e.Transaction!.SourceAccountId == first.Transaction!.SinkAccountId))
                if (second.Transaction!.SinkAccountId == first.Transaction!.SourceAccountId)
                    yield return [first, second];
    }

    private static Guid ActionId(EconomyEventV1 value) => value.Transaction?.AuthoritativeActionId
        ?? value.ItemMutation!.AuthoritativeActionId;
    private static string Reason(EconomyEventV1 value) => value.Transaction?.ReasonCode
        ?? value.ItemMutation!.ReasonCode;
    private static bool CanarySelected(EconomyProtectionProfile profile, int canaryPercentage,
        string playerSubject)
    {
        byte[] bucket = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{profile.TenantId}\0{profile.GameId}\0{profile.EnvironmentId}\0{profile.ProfileId}\0{profile.Version}\0{playerSubject}"));
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bucket) % 100
            < canaryPercentage;
    }

    private static void Add(List<EconomyFinding> output, EconomyProtectionProfile profile,
        EconomyProfileStage stage, string rule,
        IEnumerable<EconomyEventV1> matching, DateTimeOffset start, DateTimeOffset end,
        byte[] digest, IReadOnlyDictionary<string, string> fields)
    {
        Guid[] ids = matching.Select(value => value.EventId).Distinct().Order().ToArray();
        if (ids.Length > 0 && !output.Any(value => value.RuleId == rule
            && value.EventIds.SequenceEqual(ids)))
            output.Add(new EconomyFinding(rule, RuleVersion, profile.ProfileId, profile.Version,
                stage, ids, start, end, fields, digest));
    }
}
