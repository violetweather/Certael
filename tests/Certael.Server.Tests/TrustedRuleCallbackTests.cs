using Certael.Server.Rules;

namespace Certael.Server.Tests;

public sealed class TrustedRuleCallbackTests
{
    [Fact]
    public async Task TimeoutAndFailureAreIndeterminateNeverCheating()
    {
        var executor = new TrustedRuleCallbackExecutor(TimeSpan.FromMilliseconds(20));
        CancellationToken testToken = TestContext.Current.CancellationToken;
        CallbackDecision timeout = await executor.ExecuteAsync(
            "request", "state",
            async (_, _, token) => { await Task.Delay(TimeSpan.FromSeconds(5), token); return CallbackDecision.Allow(); },
            testToken);
        CallbackDecision failure = await executor.ExecuteAsync<string, string>(
            "request", "state", (_, _, _) => throw new InvalidOperationException("secret"), testToken);

        Assert.Equal(CallbackOutcome.Indeterminate, timeout.Outcome);
        Assert.Equal("CALLBACK_TIMEOUT", timeout.PublicReason);
        Assert.Equal(CallbackOutcome.Indeterminate, failure.Outcome);
        Assert.Equal("CALLBACK_FAILED", failure.PublicReason);
    }

    [Fact]
    public async Task DeveloperCancellationPropagates()
    {
        var executor = new TrustedRuleCallbackExecutor(TimeSpan.FromSeconds(1));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await executor.ExecuteAsync(
                "request", "state",
                async (_, _, token) => { await Task.Delay(1, token); return CallbackDecision.Allow(); },
                cancellation.Token));
    }
}
