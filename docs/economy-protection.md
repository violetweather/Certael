# Cross-session economy protection

Certael can evaluate authoritative ledger and item-lineage events across game
sessions. This feature is disabled until an operator installs a trusted
configuration-signing public key and uploads a signed economy profile.

It does not trust client balances, client-generated transaction identifiers, or
inventory snapshots. The game server stages `EconomyEventV1` in the same
authoritative transaction and outbox commit as the gameplay mutation.

## Event contract

`EconomyEventV1` is strict canonical Protobuf. Its source schema is
[`protocol/protobuf/certael/economy/v1/economy.proto`](../protocol/protobuf/certael/economy/v1/economy.proto).

A ledger event requires:

- a unique server-generated event and transaction ID;
- the authoritative action ID that caused the mutation;
- pseudonymous player and account subjects;
- game-defined asset identifiers and integer quantities;
- a reason code and explicit source and sink accounts; and
- at least one negative source line, one positive sink line, and a zero sum for
  every asset.

The SDK rejects a malformed or non-conserving ledger before it can be staged.
Item events record create, transfer, or destroy mutations and optional parent
lineage. Do not send email addresses, platform display names, device
fingerprints, or unrelated account identifiers.

```csharp
EconomyEventV1 economyEvent = /* create from authoritative game state */;
await EconomyProtectionEvaluator.StageAsync(transaction, economyEvent, cancellationToken);
```

`StageAsync` writes an `economy.v1` event through the authoritative transaction.
It does not publish to NATS directly and must not be called after the game
transaction has committed.

## Signed profile

An `EconomyProtectionProfile` contains immutable thresholds, a maximum 90-day
window, bounded risk and confidence, an expiry, and a non-permanent verdict
recommendation. Sign it offline with a trusted P-256 configuration key:

```csharp
using ECDsa signingKey = ECDsa.Create();
signingKey.ImportFromPem(File.ReadAllText("economy-signing-private.pem"));

var profile = new EconomyProtectionProfile(
    "competitive-default", "1.0.0", "tenant", "game", "production",
    MaximumTransactionsPerWindow: 500,
    MaximumProgressionPerWindow: 100_000,
    RepeatedRewardLimit: 3,
    Window: TimeSpan.FromDays(7),
    ExpiresAt: DateTimeOffset.UtcNow.AddDays(30),
    FindingRisk: 60,
    ConfidenceBasisPoints: 9000,
    Recommendation: VerdictRecommendation.RecommendManualReview);

SignedEconomyProtectionProfile signed =
    new EconomyProtectionProfileSigner(signingKey, "economy-2026-01").Sign(profile);
```

Keep the private key offline. Configure the Core API with the matching
`ConfigurationSigning:TrustedKeys` public PEM. Configure the analytics worker
with the same P-256 public key as an SPKI Base64 value under
`AnalyticsWorker:EconomyProfileKeys`.

Upload the four signed fields to `POST /v1/economy/profiles`. The caller needs
`economy:write` for the profile tenant and environment. A new version begins in
`Shadow`; the signed bytes and digest are immutable.

Promote with:

```text
POST /v1/economy/profiles/{profileId}/{version}/deployment
```

The body supplies `tenantId`, `gameId`, `environmentId`, `expectedStage`,
`targetStage`, and `canaryPercentage`. Canary accepts 1–99; all other stages
require zero. Valid transitions are:

```text
Shadow -> Canary | Enforced | RolledBack
Canary -> Shadow | Enforced | RolledBack
Enforced -> RolledBack
RolledBack -> Shadow
```

Promotion uses serializable PostgreSQL transactions and optimistic expected
stage checks. Enforcing a profile rolls back any prior enforced profile for the
same tenant/game/environment, and every change is appended to the profile
activity audit.

## Processing and findings

The analytics worker:

1. verifies the canonical envelope and tenant-scoped JetStream subject;
2. binds the event ID to the envelope SHA-256 receipt;
3. writes the authoritative PostgreSQL ledger or lineage projection;
4. writes rebuildable 90-day ClickHouse ledger/lineage rows;
5. updates idempotent, bounded Redis player/account/item windows;
6. verifies every active profile signature, expiry, and tenant/game/environment
   binding;
7. deterministically evaluates the player window; and
8. stores exact event IDs, authoritative fields, profile/rule versions, window,
   stage, and replay digest.

Findings also become normal evidence records visible to evidence and case APIs.
Shadow deployments always emit an effective `Observe` verdict and never open a
case. In Canary or Enforced, `Allow` and `Observe` recommendations do not open a
case; any signed recommendation that requests operator or bounded-action
handling opens or updates a case within the default 24-hour deduplication
window. Certael has no permanent-ban action.

Raw envelopes retain for at most 30 days, derived economy analytics for at most
90 days, and case metadata for at most 180 days. Player export includes economy
events, derived ledger/lineage records, findings, and relationship edges.
PostgreSQL deletion removes those player-linked records and pseudonymizes
retained case history.

## Operational checks

- Leave `EconomyProfileKeys` empty to keep analysis disabled.
- Start in Shadow and compare ordinary high-volume behavior before Canary.
- Treat an invalid signature, expired profile, or boundary mismatch as a
  configuration failure; it never authorizes a gameplay mutation.
- Monitor JetStream lag, quarantine messages, ClickHouse insert failures, Redis
  availability, case volume, and false-positive dispositions.
- Rebuild ClickHouse from JetStream/PostgreSQL; never treat it as authoritative.

## Relationship and collusion analysis

Games can stage canonical `RelationshipEventV1` edges for matches, outcomes,
trades, gifts, marketplace activity, rewards, and parties. The schema is
[`protocol/protobuf/certael/economy/v1/relationship.proto`](../protocol/protobuf/certael/economy/v1/relationship.proto).
Each event carries a server-generated event ID, the authoritative action ID,
tenant/game/environment boundary, two pseudonymous subjects, an integer weight,
and authoritative time. Do not submit device fingerprints, unrelated accounts,
display names, or cross-tenant identifiers.

```csharp
RelationshipEventV1 edge = /* derive from the committed game action */;
await new AuthoritativeTransactionRelationshipEventSink<GameState>(transaction)
    .StageAsync(edge, cancellationToken);
```

Relationship analysis is disabled until trusted public keys are configured in
`AnalyticsWorker:RelationshipProfileKeys` and a signed
`RelationshipProtectionProfile` is uploaded to
`POST /v1/relationships/profiles`. Profiles choose deterministic 7-, 30-, and/or
90-day windows and transparent thresholds. They use the same
`Shadow -> Canary -> Enforced -> RolledBack` lifecycle and optimistic deployment
API as economy profiles.

The worker stores the authoritative edge in PostgreSQL, writes a rebuildable
ClickHouse projection, verifies the profile, and evaluates reciprocal transfers,
transfer cycles, shared beneficiaries, opponent imbalance, boosting/coordinated
farming, and marketplace manipulation. Every persisted finding records the exact
edge IDs, rule version, signed profile version and stage, window, baseline,
threshold, and replay digest. Shadow findings are retained for calibration but
do not open cases; selected Canary and Enforced findings follow the signed
recommendation. No relationship finding can cause a permanent ban.
