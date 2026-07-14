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
        Assert.Equal(document.TenantId,
            RulePackCanonicalCodec.Deserialize(signed.CanonicalDocument).TenantId);
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
        var store = new RulePackLifecycleStore(TimeProvider.System,
            new RulePackVerifier(new Dictionary<string, ECDsa> { ["key"] = key }));
        SignedRulePack first = compiler.CompileAndSign(Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80));
        SignedRulePack second = compiler.CompileAndSign(Document("1.1.0", RuleDataProvenance.AuthoritativeState, 80));
        store.AddDraft(first, "author");
        store.AddDraft(second, "author");

        Assert.Throws<RuleLifecycleException>(() =>
            store.Promote("tenant", "example.inventory", "1.0.0", RuleDeploymentStage.Enforced, 0, "operator"));
        store.Approve("tenant", "example.inventory", "1.0.0", "reviewer-a");
        store.Approve("tenant", "example.inventory", "1.0.0", "reviewer-b");
        RuleDeployment initial = store.Promote(
            "tenant", "example.inventory", "1.0.0", RuleDeploymentStage.Enforced, 0, "operator");
        Assert.True(store.IsInCanary(initial, "any-session"));

        store.Approve("tenant", "example.inventory", "1.1.0", "reviewer-a");
        RuleDeployment canary = store.Promote(
            "tenant", "example.inventory", "1.1.0", RuleDeploymentStage.Canary, 10, "operator");
        bool assignment = store.IsInCanary(canary, "stable-session");
        Assert.Equal(assignment, store.IsInCanary(canary, "stable-session"));

        RuleDeployment rolledBack = store.Rollback("tenant", "example", "prod", "operator");
        Assert.Equal("1.0.0", rolledBack.Pack.Document.Version);
        Assert.Equal(RuleDeploymentStage.Enforced, rolledBack.Stage);
    }

    [Fact]
    public void PackVersionsAreImmutableAndRuleIdsUnique()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var compiler = new RulePackCompiler(key, "key");
        SignedRulePack pack = compiler.CompileAndSign(Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80));
        var store = new RulePackLifecycleStore(TimeProvider.System,
            new RulePackVerifier(new Dictionary<string, ECDsa> { ["key"] = key }));
        store.AddDraft(pack, "author");
        Assert.Throws<RuleLifecycleException>(() => store.AddDraft(pack, "author"));

        SignedRulePack tampered = pack with { Signature = new byte[pack.Signature.Length] };
        Assert.Throws<RuleLifecycleException>(() =>
            new RulePackLifecycleStore(TimeProvider.System,
                new RulePackVerifier(new Dictionary<string, ECDsa> { ["key"] = key }))
            .AddDraft(tampered, "author"));

        RulePackDocument duplicate = Document("1.0.1", RuleDataProvenance.AuthoritativeState, 80);
        duplicate = duplicate with { Rules = [duplicate.Rules[0], duplicate.Rules[0]] };
        Assert.Throws<RulePackValidationException>(() => compiler.CompileAndSign(duplicate));
    }

    [Fact]
    public void LifecycleKeysAndLookupsAreTenantScoped()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var compiler = new RulePackCompiler(key, "key");
        var store = new RulePackLifecycleStore(TimeProvider.System,
            new RulePackVerifier(new Dictionary<string, ECDsa> { ["key"] = key }));
        SignedRulePack first = compiler.CompileAndSign(Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80));
        SignedRulePack second = compiler.CompileAndSign(first.Document with { TenantId = "other-tenant" });

        store.AddDraft(first, "author");
        store.AddDraft(second, "author");

        Assert.Equal("tenant", store.Get("tenant", "example.inventory", "1.0.0").Pack.Document.TenantId);
        Assert.Equal("other-tenant", store.Get("other-tenant", "example.inventory", "1.0.0").Pack.Document.TenantId);
        Assert.Throws<RuleLifecycleException>(() => store.Get("missing", "example.inventory", "1.0.0"));
    }

    [Fact]
    public void CompilerRejectsOversizedAndInvalidExpressionsBeforeSigning()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var compiler = new RulePackCompiler(key, "key");
        RulePackDocument document = Document("1.0.0", RuleDataProvenance.AuthoritativeState, 80);
        RuleExpression tooDeep = new ConstantExpression(true);
        for (int index = 0; index < 33; index++) tooDeep = new NotExpression(tooDeep);

        Assert.Throws<RulePackValidationException>(() => compiler.CompileAndSign(document with
        {
            Rules = [document.Rules[0] with { Expression = tooDeep }]
        }));
        Assert.Throws<RulePackValidationException>(() => compiler.CompileAndSign(document with
        {
            Rules = [document.Rules[0] with
            {
                Expression = new FieldExpression("non-ascii-ä", RuleDataSource.Request)
            }]
        }));
    }

    private static RulePackDocument Document(string version, RuleDataProvenance provenance, int risk) =>
        new("tenant", "example.inventory", version, "example", "prod", 1, 1,
        [
            new RulePackRule("inventory.craft.quantity", "1.0.0", provenance,
                "inventory.craft", "INVALID_QUANTITY", risk,
                new CompareExpression(ComparisonOperator.Greater,
                    new FieldExpression("quantity", RuleDataSource.Request),
                    new ConstantExpression(0)))
        ]);
}
