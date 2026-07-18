using System.Diagnostics;
using Certael.Server.Diagnostics;

namespace Certael.Server.Actions;

public interface IAuthoritativeTransaction<TState> : IAsyncDisposable
{
    TState Current { get; }
    ulong Revision { get; }
    ValueTask<ActionReservation<TResponse>> ReserveActionAsync<TResponse>(Guid actionId,
        CancellationToken cancellationToken);
    ValueTask StageActionResultAsync<TResponse>(ActionResult<TResponse> result,
        CancellationToken cancellationToken);
    void EnqueueAuthoritativeEvent(AuthoritativeEvent authoritativeEvent);
    ValueTask<(TState State, ulong Revision)> CommitAsync(CancellationToken cancellationToken);
}

public sealed record ActionReservation<TResponse>(bool Reserved, ActionResult<TResponse>? ExistingResult)
{
    public static ActionReservation<TResponse> New() => new(true, null);
    public static ActionReservation<TResponse> Existing(ActionResult<TResponse> result) => new(false, result);
}

public sealed record AuthoritativeEvent(
    Guid EventId, Guid ActionId, string EventType, uint SchemaVersion,
    ReadOnlyMemory<byte> Payload, DateTimeOffset ServerTime);

public sealed class AuthoritativeActionHandler<TRequest, TResponse, TState>(
    ActionAuthorizer authorizer,
    IActionResultStore results,
    Func<SessionAuthorization, CancellationToken, ValueTask<IAuthoritativeTransaction<TState>>> beginTransaction,
    Func<AuthorizedAction<TRequest>, IAuthoritativeTransaction<TState>, CancellationToken,
        ValueTask<RuleDecision<TResponse>>> validateAndApply,
    ActionAdmissionPolicy? actionAdmissionPolicy = null)
{
    private sealed class ActionGate
    {
        public readonly SemaphoreSlim Semaphore = new(1, 1);
        public int Users;
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, ActionGate> ActionGates =
        new(StringComparer.Ordinal);

    public async ValueTask<ActionResult<TResponse>> HandleAsync(
        AuthorizedAction<TRequest> action,
        ActionBinding binding,
        CancellationToken cancellationToken = default)
    {
        long started = Stopwatch.GetTimestamp();
        using Activity? activity = CertaelTelemetry.Activities.StartActivity("certael.action");
        activity?.SetTag("certael.tenant", binding.TenantId);
        activity?.SetTag("certael.game", binding.GameId);
        activity?.SetTag("certael.environment", binding.EnvironmentId);
        activity?.SetTag("certael.build", binding.BuildId);
        activity?.SetTag("certael.action_type", binding.ActionType);

        ActionResult<TResponse> Complete(ActionResult<TResponse> result)
        {
            string outcome = result.Outcome.ToString().ToLowerInvariant();
            activity?.SetTag("certael.outcome", outcome);
            activity?.SetTag("certael.public_reason", result.PublicReason);
            CertaelTelemetry.RecordAction(binding.TenantId, binding.GameId, binding.EnvironmentId,
                binding.BuildId, binding.ActionType, outcome, result.PublicReason,
                Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            return result;
        }

        if (!string.IsNullOrEmpty(binding.RequestSchema)
            && (action.RequestSchema != binding.RequestSchema || action.SchemaVersion != binding.SchemaVersion))
            return Complete(ActionResult<TResponse>.Reject(action.ActionId, "SCHEMA_MISMATCH"));
        string gateKey = $"{binding.TenantId}\0{action.SessionId}\0{action.ActionId:N}";
        ActionGate gate = AcquireGate(gateKey);
        bool entered = false;
        try
        {
            await gate.Semaphore.WaitAsync(cancellationToken);
            entered = true;
            ActionResult<TResponse>? duplicate = await results.FindAsync<TResponse>(binding.TenantId, action.SessionId, action.ActionId, cancellationToken);
            if (duplicate is not null) return Complete(duplicate);

            AuthorizationDecision authorization = await authorizer.AuthorizeAsync(
                action, binding.ActionType, binding.TenantId, binding.GameId, binding.EnvironmentId,
                binding.MatchId, binding.ServerId, binding.BuildId,
                binding.ProtectionProfileId,
                actionAdmissionPolicy ?? ActionAdmissionPolicy.Default, cancellationToken);

            if (!authorization.Allowed)
                return Complete(ActionResult<TResponse>.Reject(action.ActionId, authorization.PublicReason));

            await using IAuthoritativeTransaction<TState> transaction =
                await beginTransaction(authorization.Session!, cancellationToken);
            ActionReservation<TResponse> reservation = await transaction.ReserveActionAsync<TResponse>(
                action.ActionId, cancellationToken);
            if (!reservation.Reserved) return Complete(reservation.ExistingResult!);
            RuleDecision<TResponse> decision =
                await validateAndApply(action, transaction, cancellationToken);
            ValidateDecision(decision);
            if (!decision.Allowed)
            {
                ActionResult<TResponse> rejected = ActionResult<TResponse>.Reject(
                    action.ActionId, decision.PublicReason, decision.Evidence);
                await results.StoreAsync(binding.TenantId, action.SessionId, rejected, cancellationToken);
                return Complete(rejected);
            }

            if (decision.AuthoritativeEvent is null)
                throw new InvalidOperationException("An accepted action must produce an authoritative event.");
            transaction.EnqueueAuthoritativeEvent(decision.AuthoritativeEvent);
            ulong expectedRevision = checked(transaction.Revision + 1);
            ActionResult<TResponse> accepted = ActionResult<TResponse>.Accept(
                action.ActionId, decision.Response!, expectedRevision, decision.Evidence);
            await transaction.StageActionResultAsync(accepted, cancellationToken);
            // Commit is intentionally performed after both the outbox event and
            // accepted result are staged in the authoritative transaction.
            // A transaction implementation must reject CommitAsync otherwise.
            (_, ulong revision) = await transaction.CommitAsync(cancellationToken);
            if (revision != expectedRevision)
                throw new InvalidOperationException("Authoritative transaction returned an unexpected revision.");
            await results.StoreAsync(binding.TenantId, action.SessionId, accepted, cancellationToken);
            return Complete(accepted);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch
        {
            return Complete(ActionResult<TResponse>.Indeterminate(action.ActionId));
        }
        finally
        {
            if (entered) gate.Semaphore.Release();
            if (Interlocked.Decrement(ref gate.Users) == 0)
                ActionGates.TryRemove(new KeyValuePair<string, ActionGate>(gateKey, gate));
        }
    }

    private static ActionGate AcquireGate(string key)
    {
        while (true)
        {
            ActionGate gate = ActionGates.GetOrAdd(key, static _ => new ActionGate());
            Interlocked.Increment(ref gate.Users);
            if (ActionGates.TryGetValue(key, out ActionGate? current) && ReferenceEquals(gate, current))
                return gate;
            Interlocked.Decrement(ref gate.Users);
        }
    }

    private static void ValidateDecision(RuleDecision<TResponse> decision)
    {
        if (string.IsNullOrWhiteSpace(decision.PublicReason) || decision.PublicReason.Length > 64
            || decision.PublicReason.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '_')
            || decision.Evidence.Count > 64
            || decision.Evidence.Any(field => string.IsNullOrWhiteSpace(field.Name)
                || field.Name.Length > 64 || field.Value.Length > 4096
                || field.Name.Any(char.IsControl) || field.Value.Any(char.IsControl)))
            throw new InvalidOperationException("Trusted game callback returned an invalid decision.");
    }
}

public sealed record ActionBinding(
    string ActionType, string GameId, string EnvironmentId, string MatchId,
    string ServerId, string BuildId, string RequestSchema = "", uint SchemaVersion = 1,
    string TenantId = "", string ProtectionProfileId = "", string Region = "",
    long RegionFencingEpoch = 0);

public sealed record RuleDecision<TResponse>(bool Allowed, string PublicReason, TResponse? Response,
    IReadOnlyCollection<EvidenceField> Evidence, AuthoritativeEvent? AuthoritativeEvent)
{
    public static RuleDecision<TResponse> Accept(TResponse response, AuthoritativeEvent authoritativeEvent,
        params EvidenceField[] evidence) =>
        new(true, "ACCEPTED", response, evidence, authoritativeEvent);
    public static RuleDecision<TResponse> Reject(string reason, params EvidenceField[] evidence) =>
        new(false, reason, default, evidence, null);
}
