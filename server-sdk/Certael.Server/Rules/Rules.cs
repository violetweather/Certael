namespace Certael.Server.Rules;

public interface IRule<in TRequest, in TState>
{
    string Id { get; }
    string Version { get; }
    RuleResult Evaluate(TRequest request, TState authoritativeState);
}

public sealed record RuleResult(bool Passed, string PublicReason, int RiskContribution)
{
    public static RuleResult Pass() => new(true, "PASSED", 0);
    public static RuleResult Fail(string publicReason, int riskContribution = 0) =>
        new(false, publicReason, Math.Clamp(riskContribution, 0, 100));
}

public sealed class RuleSet<TRequest, TState>(IEnumerable<IRule<TRequest, TState>> rules)
{
    private readonly IRule<TRequest, TState>[] _rules = rules.ToArray();

    public IReadOnlyList<(IRule<TRequest, TState> Rule, RuleResult Result)> Evaluate(
        TRequest request, TState authoritativeState)
    {
        var results = new List<(IRule<TRequest, TState>, RuleResult)>(_rules.Length);
        foreach (IRule<TRequest, TState> rule in _rules)
        {
            RuleResult result = rule.Evaluate(request, authoritativeState);
            results.Add((rule, result));
            if (!result.Passed) break;
        }
        return results;
    }
}
