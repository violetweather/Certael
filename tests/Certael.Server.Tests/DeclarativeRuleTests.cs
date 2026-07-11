using Certael.Server.Rules;

namespace Certael.Server.Tests;

public sealed class DeclarativeRuleTests
{
    [Fact]
    public void EvaluatesRequestAgainstAuthoritativeState()
    {
        var expression = new LogicalExpression(LogicalOperator.All,
        [
            new CompareExpression(ComparisonOperator.Greater,
                new FieldExpression("quantity", RuleDataSource.Request), new ConstantExpression(0)),
            new CompareExpression(ComparisonOperator.LessOrEqual,
                new FieldExpression("quantity", RuleDataSource.Request),
                new FieldExpression("max_craft", RuleDataSource.AuthoritativeState)),
            new CompareExpression(ComparisonOperator.Equal,
                new FieldExpression("expected_revision", RuleDataSource.Request),
                new FieldExpression("inventory.revision", RuleDataSource.AuthoritativeState)),
        ]);
        var context = new RuleEvaluationContext(
            new Dictionary<string, object?> { ["quantity"] = 2, ["expected_revision"] = 7UL },
            new Dictionary<string, object?> {
                ["max_craft"] = 5,
                ["inventory"] = new Dictionary<string, object?> { ["revision"] = 7UL }
            });

        Assert.True(new DeclarativeRuleEvaluator().Evaluate(expression, context));
    }

    [Fact]
    public void RejectsFloatingPointAndOperationExhaustion()
    {
        var floatExpression = new CompareExpression(ComparisonOperator.Equal,
            new ConstantExpression(0.1d), new ConstantExpression(0.1d));
        Assert.Throws<RuleEvaluationException>(() =>
            new DeclarativeRuleEvaluator().Evaluate(floatExpression,
                new RuleEvaluationContext(new Dictionary<string, object?>(), new Dictionary<string, object?>())));

        RuleExpression deep = new ConstantExpression(true);
        for (int index = 0; index < 20; index++) deep = new NotExpression(deep);
        Assert.Throws<RuleEvaluationException>(() =>
            new DeclarativeRuleEvaluator(5).Evaluate(deep,
                new RuleEvaluationContext(new Dictionary<string, object?>(), new Dictionary<string, object?>())));
    }
}
