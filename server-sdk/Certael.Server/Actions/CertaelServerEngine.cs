using Certael.Server.Protections;
using Certael.Server.Sessions;

namespace Certael.Server.Actions;

/// <summary>
/// Safe production entry point from an untrusted binary envelope to an
/// authoritative transaction. It deliberately exposes no signature-only API.
/// </summary>
public sealed class CertaelServerEngine(
    ActionAuthorizer authorizer,
    IActionResultStore results,
    TimeProvider timeProvider,
    ProtectionProfileVerifier profileVerifier,
    IRegionalActionFence? regionalFence = null)
{
    public async ValueTask<ActionResult<TResponse>> ValidateAndExecuteAsync<
        TRequest, TResponse, TState>(
        ReadOnlyMemory<byte> envelope,
        ActionBinding binding,
        SignedProtectionProfile signedProfile,
        Func<ReadOnlyMemory<byte>, TRequest> decodeRequest,
        Func<SessionAuthorization, CancellationToken,
            ValueTask<IAuthoritativeTransaction<TState>>> transactionFactory,
        Func<AuthorizedAction<TRequest>, IAuthoritativeTransaction<TState>, CancellationToken,
            ValueTask<RuleDecision<TResponse>>> validateAndApply,
        TimeSpan? callbackTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedProfile);
        ArgumentNullException.ThrowIfNull(decodeRequest);
        ArgumentNullException.ThrowIfNull(transactionFactory);
        ArgumentNullException.ThrowIfNull(validateAndApply);
        if (regionalFence is not null)
        {
            if (string.IsNullOrWhiteSpace(binding.Region) || binding.RegionFencingEpoch < 1)
                return ActionResult<TResponse>.Reject(Guid.Empty, "REGIONAL_LEASE_REQUIRED");
            try
            {
                if (!await regionalFence.IsCurrentOwnerAsync(new RegionalFenceRequest(
                        binding.TenantId, binding.GameId, binding.EnvironmentId, binding.MatchId,
                        binding.Region, binding.ServerId, binding.RegionFencingEpoch),
                        cancellationToken))
                    return ActionResult<TResponse>.Reject(Guid.Empty, "STALE_FENCING_EPOCH");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            { throw; }
            catch (RegionalContinuityException)
            { return ActionResult<TResponse>.Indeterminate(Guid.Empty); }
        }
        TimeSpan timeout = callbackTimeout ?? TimeSpan.FromSeconds(1);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(callbackTimeout));
        if (!profileVerifier.Verify(signedProfile))
            return ActionResult<TResponse>.Indeterminate(Guid.Empty);
        ProtectionProfile profile = signedProfile.Profile;
        if (profile.GameId != binding.GameId || profile.EnvironmentId != binding.EnvironmentId)
            throw new ArgumentException("Protection profile is bound to another game or environment.", nameof(signedProfile));
        if (!profile.ActionPolicies.TryGetValue(binding.ActionType, out ProtectionActionPolicy? policy))
            return ActionResult<TResponse>.Reject(Guid.Empty, "ACTION_NOT_REGISTERED");
        if (!string.IsNullOrEmpty(binding.RequestSchema)
            && (binding.RequestSchema != policy.RequestSchema
                || binding.SchemaVersion != policy.SchemaVersion))
            throw new ArgumentException("Action binding and protection policy schema differ.", nameof(policy));

        ActionBinding effectiveBinding = binding with
        {
            RequestSchema = policy.RequestSchema,
            SchemaVersion = policy.SchemaVersion,
            ProtectionProfileId = profile.ProfileId
        };
        var admission = new ActionAdmissionPolicy(policy.Rate.MaximumActions,
            TimeSpan.FromMilliseconds(policy.Rate.WindowMilliseconds));
        async ValueTask<RuleDecision<TResponse>> BoundedCallback(
            AuthorizedAction<TRequest> action,
            IAuthoritativeTransaction<TState> transaction,
            CancellationToken token)
        {
            using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCancellation.CancelAfter(timeout);
            return await validateAndApply(action, transaction, timeoutCancellation.Token);
        }

        var handler = new AuthoritativeActionHandler<TRequest, TResponse, TState>(
            authorizer, results, transactionFactory, BoundedCallback, admission);

        AuthorizedAction<byte[]> decoded;
        try { decoded = BinaryActionEnvelopeCodec.Decode(envelope.Span, timeProvider.GetUtcNow()); }
        catch (ActionEnvelopeException)
        {
            return ActionResult<TResponse>.Reject(Guid.Empty, "INVALID_ENVELOPE");
        }

        TRequest request;
        try { request = decodeRequest(decoded.RawPayload); }
        catch (Exception exception) when (exception is ArgumentException or FormatException
            or InvalidDataException or OverflowException)
        {
            return ActionResult<TResponse>.Reject(decoded.ActionId, "INVALID_REQUEST");
        }

        AuthorizedAction<TRequest> typed = new(decoded.SessionId, decoded.Sequence,
            decoded.ActionId, decoded.ActionType, decoded.SchemaVersion, decoded.ReceivedAt,
            decoded.ClientMonotonicMicros, request, decoded.RawPayload, decoded.PreviousDigest,
            decoded.PossessionProof, decoded.ProtocolMajor, decoded.ProtocolMinor,
            decoded.RequestSchema, decoded.SessionBindingDigest);
        return await handler.HandleAsync(typed, effectiveBinding, cancellationToken);
    }
}
