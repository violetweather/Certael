# Acceptance status

This file records evidence, not aspirations. An item is complete only when the
listed verification exists and passes in CI on every supported platform.

| Criterion | Status | Current evidence | Remaining evidence |
|---|---|---|---|
| Client cannot create authoritative state | In progress | Typed intent API and transactional .NET handler | Three executable engine sample games and adversarial E2E tests |
| Request/validate/commit/record lifecycle | Complete | Transactional handler plus live PostgreSQL tests proving game mutation, action result, and outbox event commit or roll back together | — |
| Secure ticket lifecycle | Complete | Signed 60-second tickets, key-bound challenge proof, Redis single-use redemption, persisted 30-minute sessions, server-authorized renewal, wrong-server rejection tests | — |
| Replay, reorder, duplicate, cross-binding rejection | Complete | Proof substitution, cross-match/build binding, concurrent duplicate, atomic Redis sequence+digest-chain+rate admission, PostgreSQL reservation/retry/rollback tests | — |
| Equivalent Godot, Unity, Unreal SDKs | In progress | Initial adapters and shared C ABI | Compiling Godot/Unreal implementations and engine conformance CI |
| Declarative rules and trusted callbacks | Complete | Hardened structured-YAML parser, deterministic bounded AST evaluator, signed immutable packs, trusted callbacks, timeout/failure tests | — |
| Explainable and replayable verdicts | Complete | Evidence bundles, deterministic replay digest, verdict recomputation, tenant-isolated store, tamper tests | — |
| Integrity evidence cannot cause permanent ban | Complete | Verdict API has no permanent-ban outcome; tests cap client/environment signals to manual review regardless of aggregate risk | — |
| Baseline cheat protection modules | In progress | Authoritative movement/economy/visibility guards, advisory behavioral analysis, user-mode build integrity, platform attestation interface, adversarial unit tests | Per-game calibration, official platform verifier adapters, executable sample-game integration |
| Rule shadow/canary/approval/rollback | Complete | Immutable lifecycle store, distinct approvals, shadow/canary/enforced stages, deterministic assignment, rollback tests | — |
| Tenant isolation and authorization | Complete | JWT-scope+mTLS guard tests, exact tenant/environment claims, forced PostgreSQL RLS, cross-tenant evidence tests, session-scoped action results | — |
| 100,000 concurrent players | Not verified | Horizontal architecture selected | Load harness and measured results |
| Signed artifacts, SBOM, provenance | Not started | Deterministic builds enabled | CI release pipeline and published test release |
| Secure integration under 30 minutes | Not verified | Initial installation guide | Complete packages and timed external usability test |
| No unresolved critical/high audit findings | Not verified | Threat model started | Independent security review after feature completion |

The project must not mark 1.0 or the goal complete while any row is not complete.
