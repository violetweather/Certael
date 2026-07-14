using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Concurrent;

namespace Certael.Server.Protections;

public enum AdmissionUnavailableMode { Deny }
public enum RulesUnavailableMode { Indeterminate }

public sealed record ProtectionRatePolicy(int MaximumActions, int WindowMilliseconds);
public sealed record ProtectionActionPolicy(
    string RequestSchema, uint SchemaVersion, ProtectionRatePolicy Rate,
    IReadOnlyList<string> Protections);
public sealed record ProtectionFailurePolicy(
    AdmissionUnavailableMode AdmissionStoreUnavailable,
    RulesUnavailableMode RulesUnavailable);
public sealed record ProtectionProfile(
    string TenantId, string ProfileId, string Version, string GameId, string EnvironmentId,
    IReadOnlyDictionary<string, ProtectionActionPolicy> ActionPolicies,
    ProtectionFailurePolicy FailurePolicy);
public sealed record SignedProtectionProfile(
    ProtectionProfile Profile, byte[] CanonicalDocument, byte[] Digest,
    byte[] Signature, string SigningKeyId);

public sealed class ProtectionProfileCompiler(ECDsa signingKey, string signingKeyId)
{
    private static readonly JsonSerializerOptions Json = new()
    { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    public SignedProtectionProfile CompileAndSign(ProtectionProfile profile)
    {
        byte[] canonical = Canonicalize(profile, out ProtectionProfile ordered);
        byte[] digest = SHA256.HashData(canonical);
        return new(ordered, canonical, digest, signingKey.SignHash(digest), signingKeyId);
    }

    public static byte[] Canonicalize(ProtectionProfile profile, out ProtectionProfile ordered)
    {
        Validate(profile);
        ordered = profile with
        {
            ActionPolicies = profile.ActionPolicies.OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal)
        };
        return JsonSerializer.SerializeToUtf8Bytes(ordered, Json);
    }

    public static ProtectionProfile DeserializeCanonical(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < 1 or > 1_048_576)
            throw new ProtectionProfileException("Canonical profile size is invalid.");
        ProtectionProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<ProtectionProfile>(canonical, Json)
                ?? throw new ProtectionProfileException("Canonical profile is empty.");
        }
        catch (JsonException error)
        {
            throw new ProtectionProfileException($"Canonical profile is invalid: {error.Message}");
        }
        byte[] encoded = Canonicalize(profile, out ProtectionProfile ordered);
        if (!CryptographicOperations.FixedTimeEquals(encoded, canonical))
            throw new ProtectionProfileException("Profile encoding is not canonical.");
        return ordered;
    }

    public static void Validate(ProtectionProfile profile)
    {
        Identifier(profile.TenantId); Identifier(profile.ProfileId); Identifier(profile.GameId); Identifier(profile.EnvironmentId);
        if (!System.Version.TryParse(profile.Version, out _) || profile.ActionPolicies.Count is < 1 or > 10_000)
            throw new ProtectionProfileException("Profile version or action count is invalid.");
        foreach ((string actionType, ProtectionActionPolicy policy) in profile.ActionPolicies)
        {
            Identifier(actionType); Identifier(policy.RequestSchema);
            if (policy.SchemaVersion == 0 || policy.Rate.MaximumActions is < 1 or > 100_000
                || policy.Rate.WindowMilliseconds is < 1 or > 3_600_000
                || policy.Protections.Count > 64 || policy.Protections.Any(value => { try { Identifier(value); return false; } catch { return true; } }))
                throw new ProtectionProfileException("Action policy is invalid.");
        }
    }

    private static void Identifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '_' and not '-'))
            throw new ProtectionProfileException("Identifier is invalid.");
    }
}

public sealed class ProtectionProfileVerifier(IReadOnlyDictionary<string, ECDsa> trustedKeys)
{
    public bool Verify(SignedProtectionProfile signed)
    {
        if (!trustedKeys.TryGetValue(signed.SigningKeyId, out ECDsa? key)) return false;
        byte[] canonical;
        try { canonical = ProtectionProfileCompiler.Canonicalize(signed.Profile, out _); }
        catch (ProtectionProfileException) { return false; }
        byte[] digest = SHA256.HashData(signed.CanonicalDocument);
        return CryptographicOperations.FixedTimeEquals(canonical, signed.CanonicalDocument)
            && CryptographicOperations.FixedTimeEquals(digest, signed.Digest)
            && key.VerifyHash(digest, signed.Signature);
    }
}

public enum ProtectionDeploymentStage { Draft, Shadow, Canary, Enforced, Retired }

public sealed record ProtectionProfileApproval(
    string ApproverSubject, DateTimeOffset ApprovedAt, byte[] ProfileDigest);

public sealed record ProtectionProfileDeployment(
    SignedProtectionProfile SignedProfile,
    ProtectionDeploymentStage Stage,
    int CanaryPercentage,
    IReadOnlyList<ProtectionProfileApproval> Approvals,
    DateTimeOffset UpdatedAt,
    string UpdatedBy);

/// <summary>
/// Immutable, signature-verifying lifecycle for protection profiles. Enforced
/// promotion requires two distinct approvals over the exact profile digest.
/// </summary>
public sealed class ProtectionProfileLifecycleStore(
    TimeProvider timeProvider,
    ProtectionProfileVerifier verifier)
{
    private readonly ConcurrentDictionary<string, ProtectionProfileDeployment> _deployments =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _activeByEnvironment =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Stack<string>> _history =
        new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public ProtectionProfileDeployment AddDraft(SignedProtectionProfile profile, string author)
    {
        if (!verifier.Verify(profile))
            throw new ProtectionProfileException("Profile signature or canonical document is invalid.");
        string subject = RequireSubject(author);
        string key = Key(profile.Profile);
        var deployment = new ProtectionProfileDeployment(profile, ProtectionDeploymentStage.Draft,
            0, [], timeProvider.GetUtcNow(), subject);
        if (!_deployments.TryAdd(key, deployment))
            throw new ProtectionProfileException("Profile version is immutable and already exists.");
        return deployment;
    }

    public ProtectionProfileDeployment Approve(string tenantId, string profileId, string version, string approver)
    {
        string subject = RequireSubject(approver);
        return Update(tenantId, profileId, version, current =>
        {
            if (current.Approvals.Any(value => value.ApproverSubject == subject)) return current;
            var approval = new ProtectionProfileApproval(subject, timeProvider.GetUtcNow(),
                current.SignedProfile.Digest.ToArray());
            return current with
            {
                Approvals = current.Approvals.Append(approval).ToArray(),
                UpdatedAt = timeProvider.GetUtcNow(),
                UpdatedBy = subject
            };
        });
    }

    public ProtectionProfileDeployment Promote(string tenantId, string profileId, string version,
        ProtectionDeploymentStage stage, int canaryPercentage, string operatorSubject)
    {
        if (stage is ProtectionDeploymentStage.Draft or ProtectionDeploymentStage.Retired)
            throw new ProtectionProfileException("Use add or retire for this stage.");
        if (stage == ProtectionDeploymentStage.Canary && canaryPercentage is < 1 or > 99)
            throw new ProtectionProfileException("Canary percentage must be between 1 and 99.");
        if (stage != ProtectionDeploymentStage.Canary && canaryPercentage != 0)
            throw new ProtectionProfileException("Canary percentage only applies to canary stage.");

        string subject = RequireSubject(operatorSubject);
        lock (_gate)
        {
            ProtectionProfileDeployment current = Get(tenantId, profileId, version);
            if (!verifier.Verify(current.SignedProfile))
                throw new ProtectionProfileException("Stored profile no longer verifies.");
            int requiredApprovals = stage == ProtectionDeploymentStage.Enforced ? 2 : 1;
            int approvals = current.Approvals.Select(value => value.ApproverSubject)
                .Distinct(StringComparer.Ordinal).Count();
            if (approvals < requiredApprovals)
                throw new ProtectionProfileException($"{stage} requires {requiredApprovals} distinct approvals.");
            if (current.Approvals.Any(value => !CryptographicOperations.FixedTimeEquals(
                    value.ProfileDigest, current.SignedProfile.Digest)))
                throw new ProtectionProfileException("Approval digest does not match the immutable profile.");

            ProtectionProfileDeployment promoted = current with
            {
                Stage = stage,
                CanaryPercentage = canaryPercentage,
                UpdatedAt = timeProvider.GetUtcNow(),
                UpdatedBy = subject
            };
            string key = Key(current.SignedProfile.Profile);
            _deployments[key] = promoted;
            string environment = EnvironmentKey(current.SignedProfile.Profile);
            if (stage is ProtectionDeploymentStage.Canary or ProtectionDeploymentStage.Enforced)
            {
                if (_activeByEnvironment.TryGetValue(environment, out string? prior) && prior != key)
                    _history.GetOrAdd(environment, static _ => new Stack<string>()).Push(prior);
                _activeByEnvironment[environment] = key;
            }
            return promoted;
        }
    }

    public ProtectionProfileDeployment Rollback(string tenantId, string gameId, string environmentId,
        string operatorSubject)
    {
        string environment = $"{tenantId}\0{gameId}\0{environmentId}";
        lock (_gate)
        {
            if (!_history.TryGetValue(environment, out Stack<string>? history) || history.Count == 0)
                throw new ProtectionProfileException("No prior profile is available.");
            string priorKey = history.Pop();
            ProtectionProfileDeployment prior = _deployments[priorKey];
            if (!verifier.Verify(prior.SignedProfile))
                throw new ProtectionProfileException("Rollback profile does not verify.");
            ProtectionProfileDeployment restored = prior with
            {
                Stage = ProtectionDeploymentStage.Enforced,
                CanaryPercentage = 0,
                UpdatedAt = timeProvider.GetUtcNow(),
                UpdatedBy = RequireSubject(operatorSubject)
            };
            _deployments[priorKey] = restored;
            _activeByEnvironment[environment] = priorKey;
            return restored;
        }
    }

    public bool AppliesToSession(ProtectionProfileDeployment deployment, string sessionId)
    {
        if (deployment.Stage != ProtectionDeploymentStage.Canary)
            return deployment.Stage == ProtectionDeploymentStage.Enforced;
        byte[] digest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sessionId));
        uint bucket = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(digest) % 100;
        return bucket < deployment.CanaryPercentage;
    }

    public ProtectionProfileDeployment Get(string tenantId, string profileId, string version) =>
        _deployments.TryGetValue($"{tenantId}\0{profileId}\0{version}", out ProtectionProfileDeployment? value)
            ? value : throw new ProtectionProfileException("Profile does not exist.");

    private ProtectionProfileDeployment Update(string tenantId, string profileId, string version,
        Func<ProtectionProfileDeployment, ProtectionProfileDeployment> update)
    {
        string key = $"{tenantId}\0{profileId}\0{version}";
        while (true)
        {
            ProtectionProfileDeployment current = Get(tenantId, profileId, version);
            ProtectionProfileDeployment next = update(current);
            if (_deployments.TryUpdate(key, next, current)) return next;
        }
    }

    private static string Key(ProtectionProfile value) => $"{value.TenantId}\0{value.ProfileId}\0{value.Version}";
    private static string EnvironmentKey(ProtectionProfile value) =>
        $"{value.TenantId}\0{value.GameId}\0{value.EnvironmentId}";
    private static string RequireSubject(string value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 128
            ? value : throw new ProtectionProfileException("Operator subject is invalid.");
}

public sealed class ProtectionProfileException(string message) : Exception(message);
