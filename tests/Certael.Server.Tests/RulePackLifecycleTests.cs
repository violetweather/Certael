using System.Security.Cryptography;
using Certael.Server.Rules;

namespace Certael.Server.Tests;

public sealed class RulePackLifecycleTests
{
    [Fact]
    public void SignedPackRejectsTamperingAndCapsUntrustedRisk()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        RulePackDocument document = Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80);
        SignedRulePack signed = new RulePackCompiler(key, "rules-key-1").CompileAndSign(document);
        var verifier = new RulePackVerifier(new Dictionary<string, ECDsa> { ["rules-key-1"] = key });

        Assert.True(verifier.Verify(signed));
        Assert.False(verifier.Verify(signed with { CanonicalDocument = signed.CanonicalDocument.Append((byte)0).ToArray() }));
        Assert.Throws<RulePackValidationException>(() =>
            new RulePackCompiler(key, "rules-key-1").CompileAndSign(
                Document("1.0.1", RuleDataProvenance.ClientTelemetry, 31)));
    }

    [Fact]
    public void RequiresApprovalsSupportsDeterministicCanaryAndRollback()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var compiler = new RulePackCompiler(key, "key");
        var store = new RulePackLifecycleStore(TimeProvider.System);
        SignedRulePack first = compiler.CompileAndSign(Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80));
        SignedRulePack second = compiler.CompileAndSign(Document("1.1.0", RuleDataProvenance.AuthoritativeState, 80));
        store.AddDraft(first, "author");
        store.AddDraft(second, "author");

        Assert.Throws<RuleLifecycleException>(() =>
            store.Promote("example.inventory", "1.0.0", RuleDeploymentStage.Enforced, 0, "operator"));
        store.Approve("example.inventory", "1.0.0", "reviewer-a");
        store.Approve("example.inventory", "1.0.0", "reviewer-b");
        RuleDeployment initial = store.Promote(
            "example.inventory", "1.0.0", RuleDeploymentStage.Enforced, 0, "operator");
        Assert.True(store.IsInCanary(initial, "any-session"));

        store.Approve("example.inventory", "1.1.0", "reviewer-a");
        RuleDeployment canary = store.Promote(
            "example.inventory", "1.1.0", RuleDeploymentStage.Canary, 10, "operator");
        bool assignment = store.IsInCanary(canary, "stable-session");
        Assert.Equal(assignment, store.IsInCanary(canary, "stable-session"));

        RuleDeployment rolledBack = store.Rollback("example", "prod", "operator");
        Assert.Equal("1.0.0", rolledBack.Pack.Document.Version);
        Assert.Equal(RuleDeploymentStage.Enforced, rolledBack.Stage);
    }

    [Fact]
    public void PackVersionsAreImmutableAndRuleIdsUnique()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var compiler = new RulePackCompiler(key, "key");
        SignedRulePack pack = compiler.CompileAndSign(Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80));
        var store = new RulePackLifecycleStore(TimeProvider.System);
        store.AddDraft(pack, "author");
        Assert.Throws<RuleLifecycleException>(() => store.AddDraft(pack, "author"));

        RulePackDocument duplicate = Document("1.0.1", RuleDataProvenance.AuthoritativeState, 80);
        duplicate = duplicate with { Rules = [duplicate.Rules[0], duplicate.Rules[0]] };
        Assert.Throws<RulePackValidationException>(() => compiler.CompileAndSign(duplicate));
    }

    private static RulePackDocument Document(string version, RuleDataProvenance provenance, int risk) =>
        new("example.inventory", version, "example", "prod", 1, 1,
        [
            new RulePackRule("inventory.craft.quantity", "1.0.0", provenance,
                "inventory.craft", "INVALID_QUANTITY", risk,
                new CompareExpression(ComparisonOperator.Greater,
                    new FieldExpression("quantity", RuleDataSource.Request),
                    new ConstantExpression(0)))
        ]);
}
