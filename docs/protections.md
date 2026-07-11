# Protection modules

Certael's protection modules are server-side building blocks. They do not make
the client trusted and do not automatically fit every game's physics or rules.
Integrators must configure them from authoritative game data and validate their
false-positive behavior in shadow mode.

## Atomic protocol admission

`IActionAdmissionStore` atomically enforces three properties per session:

- sequence numbers must strictly increase;
- `previous_action_digest` must equal the digest of the last admitted action;
- each action type must remain within its configured rate window.

`InMemoryActionAdmissionStore` is for tests and single-process development.
`RedisSequenceStore` implements the same decision as one Lua script for
distributed servers. Rate time comes from the Certael server clock, never the
client envelope. A rejection does not advance sequence or digest state.

Tune `ActionAdmissionPolicy` per endpoint. The default is 120 actions per 10
seconds and is intentionally generic; movement inputs and economy purchases
should not share the same production policy.

## Movement

`AuthoritativeMovementGuard` checks finite coordinates, expected revision,
server elapsed time, maximum step distance, speed, acceleration, and a game-
provided path/collision predicate. The accepted result contains the next
authoritative state and event.

This guard is a baseline, not a replacement for the game's physics simulation.
Competitive games should process player input in the authoritative simulation
and use its collision, vehicle, ability, latency-compensation, and tick rules.

## Visibility and wall-information control

`AuthoritativeVisibilityGuard` rejects actions targeting entities outside the
server-owned visible set. `FilterSnapshot` helps filter replication snapshots
before they leave the server. This is the primary defense against wallhacks:
information never sent to the client cannot be rendered by a modified client.

Visibility policy must account for audio cues, team sharing, prediction, replay,
spectator state, and deliberate reveal abilities.

## Economy

`AuthoritativeEconomyGuard` validates positive bounded debits, exact state
revision, sufficient funds, and checked arithmetic. It must run inside the same
authoritative transaction that records the balance and resulting asset. Prices,
inventory, offers, and rewards must be loaded from server state.

## Behavioral observations

`BehavioralAnalyzer` evaluates server-observed input timing and view changes for
non-monotonic input, improbably regular automation, and repeated rapid view
snaps. These are advisory findings: accessibility tools, unusual hardware,
network batching, and skilled play can resemble automation.

Do not reject gameplay or punish an account from one behavioral window. Combine
multiple server-observed windows with authoritative contradictions, calibrated
per-game baselines, shadow evaluation, and review.

## User-mode integrity

`UserModeIntegrityVerifier` compares a client-reported build identifier and file
manifest with a server-approved manifest, checks freshness, and records debugger
observation. A report must be tied to a fresh server challenge by the integration.
Because the client can patch the reporter, findings are `ClientOnly`, capped at
low risk, and cannot recommend a kick or suspension by themselves.

This module does not scan arbitrary user files, inject into other processes, or
install a kernel driver. Collect only the minimum game-process data permitted by
platform rules and the game's privacy notice.

## Platform attestation

`PlatformAttestationService` accepts an integration-specific
`IPlatformAttestationVerifier`. The verifier must validate the platform vendor's
signature, certificate chain, application identity, freshness, and exact server
nonce. Failed attestation is environmental evidence and remains insufficient for
permanent account action.

Platform adapters are not bundled yet; each platform requires its official SDK,
credentials, policies, and server-side verification service.
