# Certael normative security contract

This document defines Certael's 1.0 security claim. **MUST**, **MUST NOT**,
**SHOULD**, and **MAY** describe normative requirements.

## Trust boundary

The player controls the client computer. The client and all client-produced data
are untrusted, including encrypted, signed, attested, obfuscated, or Certael-
reported data. Dedicated game servers and correctly isolated Certael backend
workloads are trusted to enforce their published policy.

Only the authoritative game server may commit gameplay state. A client MUST send
typed intent rather than a claimed outcome. A signature proves possession of an
ephemeral session key only.

## Guaranteed when integrated correctly

Certael MUST:

- bind bootstrap tickets to tenant, game, environment, pseudonymous player,
  match, authoritative server, build, protection profile, signing-key scope,
  protocol range, and ephemeral public key;
- limit tickets to 60 seconds, redeem them once, and verify key possession;
- reject altered proofs, expired or revoked sessions, binding substitution,
  replay, reorder, duplicate mutation, broken digest chains, and rate excess;
- evaluate protected actions against server-owned state;
- atomically commit an accepted mutation, idempotent result, and authoritative
  event, or commit none;
- return `Indeterminate` when it cannot safely determine a commit outcome;
- verify immutable signed rule and protection documents before activation;
- preserve tenant boundaries in authorization, storage, evidence, and audit;
- prevent client-only or environmental findings from independently causing an
  account-level punishment.

## Not guaranteed

Certael does not guarantee that:

- a validly signed request is honest;
- the client binary, operating system, or in-memory key is uncompromised;
- aim assistance, bots, macros, overlays, automation, or altered rendering are
  always detected;
- hidden information remains hidden after a server sends it to the client;
- peer/listen servers provide dedicated-server assurance;
- generic helpers replace the game's authoritative simulation;
- Certael prevents compromise of a trusted server or operator identity.

## Failure rules

- Missing or unverifiable authentication MUST fail closed.
- Unavailable replay/admission state MUST deny an action.
- Rule or transaction uncertainty MUST return `Indeterminate`.
- Clients MUST reconcile authoritative state after `Indeterminate` and MUST NOT
  repeat a valuable operation with a new action ID.
- Missing native libraries MUST stop protected initialization and MUST NOT create
  a dummy or permissive implementation.

## Enforcement and privacy

Certael MAY reject an action and recommend observation, increased sampling,
restriction, kick, temporary suspension, or manual review. The game operator
owns bans, identity, appeals, and legal policy. Certael 1.0 has no permanent-ban
recommendation.

Integrations MUST pseudonymize player subjects, minimize telemetry, redact
secrets, restrict evidence access, audit reads, enforce retention, and provide
required deletion/export hooks.

## Deployment assurance

Dedicated authoritative servers are the high-assurance model. Peer/listen hosts
MUST be labeled reduced assurance. Production MUST use TLS, workload identity,
external secrets, durable PostgreSQL/Redis, signed releases, and tested backup,
rotation, and revocation procedures.
