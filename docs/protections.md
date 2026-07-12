# Protection modules

Certael's protection modules are server-side building blocks. They do not make
the client trusted and do not automatically fit every game's physics or rules.
Integrators must configure them from authoritative game data and validate their
false-positive behavior in shadow mode.

## Atomic protocol admission

`IActionAdmissionStore` atomically enforces three properties per session:

- sequence numbers must equal the exact next value from the session's initial
  sequence;
- `previous_action_digest` must equal the digest of the last admitted action;
- each action type must remain within its configured rate window.

`InMemoryActionAdmissionStore` is for tests and single-process development.
`RedisSequenceStore` implements the same decision as one Lua script for
distributed servers. Rate time comes from the Certael server clock, never the
client envelope. Sequences must be contiguous; a skipped value returns
`SEQUENCE_GAP`. Replay, chain, and gap failures do not advance admission state.
A correctly signed, contiguous action rejected only for rate excess **does**
consume its sequence and digest. This lets the next client action continue the
chain instead of permanently desynchronizing the session.

Redis replay and rate keys include a deterministic tenant/environment namespace
and use one cluster hash slot per session so the Lua admission operation remains
atomic on Redis Cluster. Ticket-redemption keys use the same tenant/environment
isolation principle.

Tune `ActionAdmissionPolicy` per endpoint. The default is 120 actions per 10
seconds and is intentionally generic; movement inputs and economy purchases
should not share the same production policy.

## Signed protection profiles

A `SignedProtectionProfile` binds immutable action policy to one game and
environment. Each action registration supplies its request schema/version, rate
window, and enabled protection names. Admission-store failure is deny-only;
rule uncertainty returns `Indeterminate`.

`ProtectionProfileLifecycleStore` verifies the profile signature when a draft is
added. Shadow and canary promotion require an approval over the exact digest;
enforcement requires two distinct approvers. Canary assignment is deterministic
per session, and rollback reactivates the prior verified profile. The current
lifecycle store is in-memory; production persistence and authenticated profile
administration remain a documented pre-1.0 gate.

`CertaelServerEngine.ValidateAndExecuteAsync` accepts the signed profile rather
than a loose action policy. It verifies the signature and game/environment
binding, locates the registered action, applies that schema/rate policy, and
requires the active session to carry the same profile ID.

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

`BehavioralAnalyzer` evaluates server-observed windows for non-monotonic input,
improbably regular automation, repeated rapid view snaps, extreme view
acceleration, repeated sub-50 ms action-to-target reactions, and repeated
identical path steps. Findings include their deterministic rule version and the
features used. Optional network, input-device, target-availability, and position
context helps a game calibrate thresholds.

All behavioral findings remain advisory. Accessibility tools, unusual hardware,
network batching, deterministic game movement, and highly skilled play can
resemble automation. Raw observation retention must be short and configured by
the game operator.

Do not reject gameplay or punish an account from one behavioral window. Combine
multiple server-observed windows with authoritative contradictions, calibrated
per-game baselines, shadow evaluation, and review.

## User-mode integrity

`UserModeIntegrityVerifier` compares a client-reported build identifier and file
manifest with a server-approved manifest, verifies the exact fresh server
challenge in constant time, checks freshness, bounds module reporting, and
records debugger observation. The caller must generate and retire each challenge
on the trusted server.
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
