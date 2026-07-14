using System.Security.Cryptography;
using Certael.Server.Protections;

namespace Certael.Server.Tests;

public sealed class ProtectionProfileTests
{
    [Fact]
    public void SignedProfileDetectsPolicySubstitution()
    {
        using ECDsa key = ECDsa.Create();
        var profile = new ProtectionProfile("tenant", "competitive", "1.0.0", "game", "prod",
            new Dictionary<string, ProtectionActionPolicy>
            {
                ["inventory.craft"] = new("example.Craft.v1", 1, new(10, 10_000), ["economy", "revision"])
            }, new(AdmissionUnavailableMode.Deny, RulesUnavailableMode.Indeterminate));
        SignedProtectionProfile signed = new ProtectionProfileCompiler(key, "rules-key").CompileAndSign(profile);
        var verifier = new ProtectionProfileVerifier(new Dictionary<string, ECDsa> { ["rules-key"] = key });
        Assert.True(verifier.Verify(signed));
        Assert.Equal(profile.TenantId,
            ProtectionProfileCompiler.DeserializeCanonical(signed.CanonicalDocument).TenantId);
        Assert.False(verifier.Verify(signed with { Profile = profile with { EnvironmentId = "other" } }));
    }

    [Fact]
    public void ProfileLifecycleRequiresVerifiedApprovalsAndSupportsRollback()
    {
        using ECDsa key = ECDsa.Create();
        var compiler = new ProtectionProfileCompiler(key, "profile-key");
        var verifier = new ProtectionProfileVerifier(
            new Dictionary<string, ECDsa> { ["profile-key"] = key });
        var lifecycle = new ProtectionProfileLifecycleStore(TimeProvider.System, verifier);
        SignedProtectionProfile first = compiler.CompileAndSign(Profile("1.0.0"));
        SignedProtectionProfile second = compiler.CompileAndSign(Profile("1.1.0"));
        lifecycle.AddDraft(first, "author");
        lifecycle.AddDraft(second, "author");

        lifecycle.Approve("tenant", "competitive", "1.0.0", "reviewer-a");
        lifecycle.Approve("tenant", "competitive", "1.0.0", "reviewer-b");
        lifecycle.Promote("tenant", "competitive", "1.0.0", ProtectionDeploymentStage.Enforced, 0, "operator");
        lifecycle.Approve("tenant", "competitive", "1.1.0", "reviewer-a");
        ProtectionProfileDeployment canary = lifecycle.Promote(
            "tenant", "competitive", "1.1.0", ProtectionDeploymentStage.Canary, 10, "operator");
        Assert.Equal(lifecycle.AppliesToSession(canary, "session"),
            lifecycle.AppliesToSession(canary, "session"));

        ProtectionProfileDeployment restored = lifecycle.Rollback("tenant", "game", "prod", "operator");
        Assert.Equal("1.0.0", restored.SignedProfile.Profile.Version);
        Assert.Equal(ProtectionDeploymentStage.Enforced, restored.Stage);

        SignedProtectionProfile tampered = first with { Signature = new byte[first.Signature.Length] };
        Assert.Throws<ProtectionProfileException>(() =>
            new ProtectionProfileLifecycleStore(TimeProvider.System, verifier)
                .AddDraft(tampered, "author"));
    }

    [Fact]
    public void ProfileLifecycleIsTenantScoped()
    {
        using ECDsa key = ECDsa.Create();
        var compiler = new ProtectionProfileCompiler(key, "profile-key");
        var lifecycle = new ProtectionProfileLifecycleStore(TimeProvider.System,
            new ProtectionProfileVerifier(new Dictionary<string, ECDsa> { ["profile-key"] = key }));
        SignedProtectionProfile first = compiler.CompileAndSign(Profile("1.0.0"));
        SignedProtectionProfile second = compiler.CompileAndSign(
            first.Profile with { TenantId = "other-tenant" });

        lifecycle.AddDraft(first, "author");
        lifecycle.AddDraft(second, "author");

        Assert.Equal("tenant", lifecycle.Get("tenant", "competitive", "1.0.0").SignedProfile.Profile.TenantId);
        Assert.Equal("other-tenant", lifecycle.Get("other-tenant", "competitive", "1.0.0").SignedProfile.Profile.TenantId);
        Assert.Throws<ProtectionProfileException>(() => lifecycle.Get("missing", "competitive", "1.0.0"));
    }

    private static ProtectionProfile Profile(string version) =>
        new("tenant", "competitive", version, "game", "prod",
            new Dictionary<string, ProtectionActionPolicy>
            {
                ["inventory.craft"] = new("example.Craft.v1", 1, new(10, 10_000),
                    ["economy", "revision"])
            }, new(AdmissionUnavailableMode.Deny, RulesUnavailableMode.Indeterminate));
}
