using Certael.Server.Rules;

namespace Certael.Server.Tests;

public sealed class RulePackYamlParserTests
{
    [Fact]
    public void ParsesAndEvaluatesShippedInventoryPack()
    {
        string yaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "inventory.yaml"));
        RulePackDocument document = new RulePackYamlParser().Parse(yaml);
        RulePackCompiler.Validate(document);
        Assert.Equal(2, document.Rules.Count);

        RulePackRule quantity = document.Rules.Single(rule => rule.RuleId.EndsWith("positive_quantity", StringComparison.Ordinal));
        var evaluator = new DeclarativeRuleEvaluator();
        Assert.True(evaluator.Evaluate(quantity.Expression,
            new RuleEvaluationContext(new Dictionary<string, object?> { ["quantity"] = 5L },
                new Dictionary<string, object?>())));
        Assert.False(evaluator.Evaluate(quantity.Expression,
            new RuleEvaluationContext(new Dictionary<string, object?> { ["quantity"] = 101L },
                new Dictionary<string, object?>())));
    }

    [Fact]
    public void RejectsUnknownFieldsAndStructuralExhaustion()
    {
        const string unknown = """
            apiVersion: certael.dev/v1
            kind: RulePack
            malicious: true
            metadata: {}
            compatibility: {}
            rules: []
            """;
        Assert.Throws<RulePackValidationException>(() => new RulePackYamlParser().Parse(unknown));

        string deep = "apiVersion: certael.dev/v1\nkind: RulePack\nmetadata: " +
            string.Concat(Enumerable.Repeat("{x: ", 40)) + "1" + string.Concat(Enumerable.Repeat("}", 40));
        Assert.Throws<RulePackValidationException>(() => new RulePackYamlParser(maximumDepth: 10).Parse(deep));
    }
}
