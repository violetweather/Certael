using System.Collections.Immutable;

namespace Certael.Server.Actions;

public enum ActionOutcome { Accepted, Rejected, Indeterminate }

public sealed record AuthorizedAction<TRequest>(
    string SessionId,
    ulong Sequence,
    Guid ActionId,
    string ActionType,
    uint SchemaVersion,
    DateTimeOffset ReceivedAt,
    long ClientMonotonicMicros,
    TRequest Request,
    ReadOnlyMemory<byte> RawPayload,
    ReadOnlyMemory<byte> PreviousDigest,
    ReadOnlyMemory<byte> PossessionProof);

public sealed record ActionResult<TResponse>(
    Guid ActionId,
    ActionOutcome Outcome,
    string PublicReason,
    TResponse? Response,
    ulong AuthoritativeRevision,
    ImmutableArray<EvidenceField> Evidence)
{
    public static ActionResult<TResponse> Accept(Guid id, TResponse response, ulong revision,
        IEnumerable<EvidenceField>? evidence = null) =>
        new(id, ActionOutcome.Accepted, "ACCEPTED", response, revision,
            evidence?.ToImmutableArray() ?? []);

    public static ActionResult<TResponse> Reject(Guid id, string publicReason,
        IEnumerable<EvidenceField>? evidence = null) =>
        new(id, ActionOutcome.Rejected, publicReason, default, 0,
            evidence?.ToImmutableArray() ?? []);

    public static ActionResult<TResponse> Indeterminate(Guid id) =>
        new(id, ActionOutcome.Indeterminate, "INDETERMINATE", default, 0, []);
}

public enum Provenance { ClientClaim, ClientTelemetry, GameServerObservation, AuthoritativeState, CertaelDerived }

public sealed record EvidenceField(string Name, string Value, Provenance Provenance, bool Sensitive = false);
