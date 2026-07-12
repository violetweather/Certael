using System.Security.Cryptography;
using Certael.Server.Protections;

namespace Certael.Server.Tests;

public sealed class ProtectionProfileTests
{
    [Fact]
    public void SignedProfileDetectsPolicySubstitution()
    {
        using ECDsa key = ECDsa.Create();
        var profile = new ProtectionProfile("competitive", "1.0.0", "game", "prod",
            new Dictionary<string, ProtectionActionPolicy>
            {
                ["inventory.craft"] = new("example.Craft.v1", 1, new(10, 10_000), ["economy", "revision"])
            }, new(AdmissionUnavailableMode.Deny, RulesUnavailableMode.Indeterminate));
        SignedProtectionProfile signed = new ProtectionProfileCompiler(key, "rules-key").CompileAndSign(profile);
        var verifier = new ProtectionProfileVerifier(new Dictionary<string, ECDsa> { ["rules-key"] = key });
        Assert.True(verifier.Verify(signed));
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

        lifecycle.Approve("competitive", "1.0.0", "reviewer-a");
        lifecycle.Approve("competitive", "1.0.0", "reviewer-b");
        lifecycle.Promote("competitive", "1.0.0", ProtectionDeploymentStage.Enforced, 0, "operator");
        lifecycle.Approve("competitive", "1.1.0", "reviewer-a");
        ProtectionProfileDeployment canary = lifecycle.Promote(
            "competitive", "1.1.0", ProtectionDeploymentStage.Canary, 10, "operator");
        Assert.Equal(lifecycle.AppliesToSession(canary, "session"),
            lifecycle.AppliesToSession(canary, "session"));

        ProtectionProfileDeployment restored = lifecycle.Rollback("game", "prod", "operator");
        Assert.Equal("1.0.0", restored.SignedProfile.Profile.Version);
        Assert.Equal(ProtectionDeploymentStage.Enforced, restored.Stage);

        SignedProtectionProfile tampered = first with { Signature = new byte[first.Signature.Length] };
        Assert.Throws<ProtectionProfileException>(() =>
            new ProtectionProfileLifecycleStore(TimeProvider.System, verifier)
                .AddDraft(tampered, "author"));
    }

    private static ProtectionProfile Profile(string version) =>
        new("competitive", version, "game", "prod",
            new Dictionary<string, ProtectionActionPolicy>
            {
                ["inventory.craft"] = new("example.Craft.v1", 1, new(10, 10_000),
                    ["economy", "revision"])
            }, new(AdmissionUnavailableMode.Deny, RulesUnavailableMode.Indeterminate));
}
