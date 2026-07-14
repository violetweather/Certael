# Acceptance status

This file records evidence, not aspirations. An item is complete only when the
listed verification exists and passes in CI on every supported platform.

| Criterion | Status | Current evidence | Remaining evidence |
|---|---|---|---|
| Client cannot create authoritative state | In progress | Typed intent API and transactional .NET handler | Three executable engine sample games and adversarial E2E tests |
| Canonical protocol v1 | In progress | Strict canonical action codec in Rust/.NET, deterministic binary ticket claims, versioned C ABI, native verifier, golden vector and negative tests | Complete engine conformance and external protocol review |
| Request/validate/commit/record lifecycle | In progress | Transactional handler plus a local disposable PostgreSQL run proving game mutation, action result, and outbox event commit or roll back together | Passing protected CI and multi-replica crash/failover evidence |
| Secure ticket lifecycle | In progress | 60-second canonical binary tickets, key proof, durable tenant-isolated PostgreSQL single-use redemption, absolute lifetime, individual/bulk revocation, overlapping signing-key ring and KMS/HSM provider interface | Production KMS adapter and rotation/revocation rehearsal |
| Replay, reorder, duplicate, cross-binding rejection | In progress | Local proof substitution, cross-match/build/profile binding, concurrent duplicate, atomic Redis sequence+digest-chain+rate admission, and PostgreSQL rollback tests | Protected CI, failover, and multi-replica evidence |
| Equivalent Godot, Unity, Unreal SDKs | In progress | Typed binary adapters, versioned C ABI, native verifier, Godot/Unity Agent lifecycle relays, Unity .NET Standard compatibility build, local Godot 4.7-compatible macOS arm64 native build, and packaging workflow | Pinned-editor Unreal/Unity IL2CPP execution and executable samples; cross-platform Agent relay E2E |
| Declarative rules and trusted callbacks | Complete | Hardened structured-YAML parser, deterministic bounded AST evaluator, signed immutable packs, trusted callbacks, timeout/failure tests | — |
| Explainable and replayable verdicts | Complete | Evidence bundles, deterministic replay digest, verdict recomputation, tenant-isolated store, tamper tests | — |
| Integrity evidence cannot cause permanent ban | Complete | Verdict API has no permanent-ban outcome; tests cap client/environment signals to manual review regardless of aggregate risk | — |
| Baseline cheat protection modules | In progress | Authoritative movement/economy/visibility guards, advisory behavioral analysis, user-mode build integrity, durable tenant-isolated approved/revoked Agent build registry, platform attestation interface, adversarial unit tests | Per-game calibration, official platform verifier adapters, executable sample-game integration |
| Rule/profile shadow/canary/approval/rollback | In progress | Agent policies, signed rule packs, and protection profiles have immutable tenant binding, durable PostgreSQL storage, tenant RLS, digest-bound distinct approvals, shadow/canary/enforced stages, authenticated administration, audit linkage, retirement, and rollback exercised against disposable PostgreSQL | Multi-replica failure and operator usability testing |
| Tenant isolation and authorization | In progress | Tenant-scoped store APIs, forced RLS for sessions/results/outbox/evidence/audit/Agent policies/configurations/approvals, explicit certificate-chain plus token binding, environment-scoped privacy deletion, and a local `NOBYPASSRLS` integration test | Protected CI and production-role review |
| 100,000 concurrent players | Not verified | Local protocol load harness exists | Distributed 100k-session/25k admission load, burst, failover, and 24-hour soak results |
| Signed artifacts, SBOM, provenance | In progress | Pinned pre-release workflow for native/engine/NuGet/container packages, nonempty SBOM, checksums, attestations, and local packaging verification | Independently verify a release, platform signing/notarization, and complete the SLSA assessment |
| Secure integration under 30 minutes | Not verified | Prebuilt-package guide plus README Godot session and optional Agent quickstart | Release-package usability run and timed external developer test |
| No unresolved critical/high audit findings | Not verified | Threat model started | Independent security review after feature completion |

The project must not mark 1.0 or the goal complete while any row is not complete.
