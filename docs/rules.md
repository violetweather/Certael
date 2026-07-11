# Custom game rules

Certael rules express game invariants, not guesses about whether a player looks
human. A strong rule compares a typed request with authoritative state: available
currency, inventory revision, cooldown, ownership, turn, position limits, race
checkpoint order, or server-observed timing.

## Choose the right rule type

- **Declarative rules** are bounded comparisons over request and authoritative
  state. They are portable, deterministic, reviewable, and operation-limited.
- **Trusted callbacks** run game-server code for domain logic that cannot be
  expressed declaratively. They have explicit timeouts and fail indeterminate.

Never execute rule code supplied by a game client.

## Rule-pack structure

Start from `rules/examples/inventory.yaml`:

```yaml
apiVersion: certael.dev/v1
kind: RulePack
metadata:
  id: example.inventory
  version: 1.0.0
  gameId: example
  environmentId: development
compatibility:
  protocolMinimum: 1
  protocolMaximum: 1
actions:
  inventory.craft:
    requestSchema: example.CraftItemRequest
rules:
  - id: inventory.craft.positive_quantity
    version: 1.0.0
    provenance: ClientClaim
    actionType: inventory.craft
    publicFailureReason: INVALID_QUANTITY
    maximumRiskContribution: 0
    expression:
      compare:
        operator: Greater
        left: { field: { source: Request, path: quantity } }
        right: { constant: 0 }
```

Supported expression nodes are `constant`, `field`, `compare`, `logical`, and
`not`. Field sources are `Request` and `AuthoritativeState`. Comparisons support
`Equal`, `NotEqual`, `Less`, `LessOrEqual`, `Greater`, and `GreaterOrEqual`;
logical operators are `All` and `Any`.

The evaluator defaults to 256 operations, paths no deeper than 16 fields, and at
most 64 logical operands. Missing or invalid fields fail evaluation rather than
silently becoming trusted defaults.

## Provenance and risk

Label evidence by origin. Client claims, client telemetry, integrity observations,
and platform attestation remain untrusted or environmental. The compiler caps
specified untrusted/environmental contributions at 30. Permanent account action
must require authoritative corroboration and human-review policy, never only a
client-integrity signal.

Use stable public failure reasons containing letters, digits, and underscores,
up to 64 characters. Keep sensitive diagnostic detail in access-controlled
evidence, not the public response.

## Validate and sign

```bash
dotnet run --project cli/Certael.Cli -- \
  rules validate rules/examples/inventory.yaml

dotnet run --project cli/Certael.Cli -- \
  rules sign rules/examples/inventory.yaml /secure/rules-private.pem rules-2026-q3 \
  artifacts/example.inventory-1.0.0.json
```

Use a P-256 ECDSA PEM private key kept in a managed signing service or protected
offline workflow. Distribute only the public verification key to runtime
services. A signed pack covers its canonical document and SHA-256 digest.

Rule-pack versions are immutable. Create a new version for every change.

## Trusted callbacks

Wrap game-specific callbacks with `TrustedRuleCallbackExecutor`. Configure a
small timeout appropriate to the action; the implementation permits at most 30
seconds. Timeouts, exceptions, invalid reasons, or oversized evidence become
`Indeterminate`, not an allow.

Callbacks must:

- read state from the authoritative transaction;
- honor cancellation;
- avoid external side effects before commit;
- return bounded, non-sensitive public reasons;
- produce evidence with intentional provenance;
- remain deterministic for the same trusted inputs where possible.

## Safe deployment lifecycle

1. Add the immutable signed pack as `Draft`.
2. Obtain one distinct approval for `Shadow` or `Canary`.
3. Compare shadow decisions with actual authoritative outcomes and investigate
   false positives.
4. Canary to 1–99% of sessions using stable session bucketing.
5. Require two distinct digest-bound approvals for `Enforced`.
6. Monitor rejection rate, latency, indeterminate results, and player impact.
7. Roll back to the recorded prior deployment when thresholds are exceeded.

Approvals and promotion APIs currently exist in the server SDK; a production
operator must expose them through an authenticated, audited control plane.

## Genre examples

| System | Request | Authoritative checks |
|---|---|---|
| Inventory | craft recipe and quantity | recipe exists, ingredients, revision, capacity |
| Economy | buy offer | server price, balance, offer window, idempotency |
| Racing | cross checkpoint | expected checkpoint, track bounds, server time |
| Card game | play card | ownership, turn, mana, legal target |
| Strategy | issue order | unit ownership, visibility, cooldown, resources |
| Movement | request movement | server simulation, acceleration envelope, collision |
| Social | trade/transfer | ownership, recipient policy, escrow, transaction limits |

For high-frequency movement, do not create a database transaction for every
render frame. Validate batched inputs or simulation commands inside the server's
authoritative tick model and record material outcomes.
