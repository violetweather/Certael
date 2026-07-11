namespace Certael.Server.Rules;

public enum CallbackOutcome { Allowed, Rejected, Indeterminate }

public sealed record CallbackDecision(
    CallbackOutcome Outcome,
    string PublicReason,
    IReadOnlyDictionary<string, string> Evidence)
{
    public static CallbackDecision Allow(IReadOnlyDictionary<string, string>? evidence = null) =>
        new(CallbackOutcome.Allowed, "ALLOWED", evidence ?? new Dictionary<string, string>());
    public static CallbackDecision Reject(string publicReason,
        IReadOnlyDictionary<string, string>? evidence = null) =>
        new(CallbackOutcome.Rejected, publicReason, evidence ?? new Dictionary<string, string>());
    public static CallbackDecision Indeterminate(string reason) =>
        new(CallbackOutcome.Indeterminate, reason, new Dictionary<string, string>());
}

public sealed class TrustedRuleCallbackExecutor(TimeSpan timeout)
{
    public async ValueTask<CallbackDecision> ExecuteAsync<TRequest, TState>(
        TRequest request,
        TState authoritativeState,
        Func<TRequest, TState, CancellationToken, ValueTask<CallbackDecision>> callback,
        CancellationToken cancellationToken = default)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        ArgumentNullException.ThrowIfNull(callback);
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(timeout);
        try
        {
            CallbackDecision decision = await callback(
                request, authoritativeState, timeoutCancellation.Token);
            return Validate(decision);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return CallbackDecision.Indeterminate("CALLBACK_TIMEOUT");
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return CallbackDecision.Indeterminate("CALLBACK_FAILED");
        }
    }

    private static CallbackDecision Validate(CallbackDecision decision)
    {
        if (string.IsNullOrWhiteSpace(decision.PublicReason) || decision.PublicReason.Length > 64)
            return CallbackDecision.Indeterminate("INVALID_CALLBACK_RESULT");
        if (decision.Evidence.Count > 64
            || decision.Evidence.Any(item => item.Key.Length > 64 || item.Value.Length > 1024))
            return CallbackDecision.Indeterminate("INVALID_CALLBACK_RESULT");
        return decision;
    }
}
