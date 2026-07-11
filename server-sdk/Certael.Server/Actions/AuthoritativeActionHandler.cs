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
        ValueTask<RuleDecision<TResponse>>> validateAndApply)
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, SemaphoreSlim> _actionGates = new();

    public async ValueTask<ActionResult<TResponse>> HandleAsync(
        AuthorizedAction<TRequest> action,
        ActionBinding binding,
        CancellationToken cancellationToken = default)
    {
        SemaphoreSlim gate = _actionGates.GetOrAdd(action.ActionId, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            ActionResult<TResponse>? duplicate = await results.FindAsync<TResponse>(action.SessionId, action.ActionId, cancellationToken);
            if (duplicate is not null) return duplicate;

            AuthorizationDecision authorization = await authorizer.AuthorizeAsync(
                action, binding.ActionType, binding.GameId, binding.EnvironmentId,
                binding.MatchId, binding.ServerId, binding.BuildId, cancellationToken);

            if (!authorization.Allowed)
                return ActionResult<TResponse>.Reject(action.ActionId, authorization.PublicReason);

            await using IAuthoritativeTransaction<TState> transaction =
                await beginTransaction(authorization.Session!, cancellationToken);
            ActionReservation<TResponse> reservation = await transaction.ReserveActionAsync<TResponse>(
                action.ActionId, cancellationToken);
            if (!reservation.Reserved) return reservation.ExistingResult!;
            RuleDecision<TResponse> decision =
                await validateAndApply(action, transaction, cancellationToken);
            if (!decision.Allowed)
            {
                ActionResult<TResponse> rejected = ActionResult<TResponse>.Reject(
                    action.ActionId, decision.PublicReason, decision.Evidence);
                await results.StoreAsync(action.SessionId, rejected, cancellationToken);
                return rejected;
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
            await results.StoreAsync(action.SessionId, accepted, cancellationToken);
            return accepted;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch
        {
            return ActionResult<TResponse>.Indeterminate(action.ActionId);
        }
        finally
        {
            gate.Release();
            _actionGates.TryRemove(new KeyValuePair<Guid, SemaphoreSlim>(action.ActionId, gate));
        }
    }
}

public sealed record ActionBinding(
    string ActionType, string GameId, string EnvironmentId, string MatchId,
    string ServerId, string BuildId);

public sealed record RuleDecision<TResponse>(bool Allowed, string PublicReason, TResponse? Response,
    IReadOnlyCollection<EvidenceField> Evidence, AuthoritativeEvent? AuthoritativeEvent)
{
    public static RuleDecision<TResponse> Accept(TResponse response, AuthoritativeEvent authoritativeEvent,
        params EvidenceField[] evidence) =>
        new(true, "ACCEPTED", response, evidence, authoritativeEvent);
    public static RuleDecision<TResponse> Reject(string reason, params EvidenceField[] evidence) =>
        new(false, reason, default, evidence, null);
}
