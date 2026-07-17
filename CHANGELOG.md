# Changelog

All notable changes to Certael Core are documented here. Certael follows semantic versioning for public contracts; prerelease APIs may evolve only through explicit versioned contracts and feature flags.

## [0.4.0-alpha.1] - 2026-07-17

### Added

- Durable transactional event delivery with a lease-based PostgreSQL outbox, NATS JetStream deduplication, retry/dead-letter administration, tenant catalog authorization, replay, lag telemetry, and rebuildable ClickHouse projections.
- Normalized evidence, verdict, case, assignment, note, disposition, activity, bounded-action, privacy-export, and deletion-pseudonymization workflows under forced tenant RLS.
- A dark, WCAG 2.2 AA operator console and delegated OIDC/mTLS BFF for evidence investigation, case operations, relationship analysis, bounded decisions, and audit reconstruction.
- Canonical `EconomyEventV1` ledger and item-lineage events, PostgreSQL projections, signed staged profiles, deterministic conservation/duplication/lineage/reward/progression/velocity/cycle findings, and exact replay digests.
- Explainable 7/30/90-day relationship analysis for reciprocal transfers, cycles, shared beneficiaries, opponent imbalance, boosting/farming, and marketplace manipulation.
- Isolated Steam, Epic Online Services, PlayFab, and Agones integration packages with authoritative backend verification boundaries.
- Distinct platform identity and nonce-bound platform-attestation interfaces and signed required/optional policy evaluation. Steam/EOS login assertions are never labeled device attestation.
- `@certael/server` for Node 22+ ESM with atomic `handleAction()`, typed Core clients, store abstractions, replay digests, and a Rust Node-API verifier.
- Signed sandboxed WASM rule contracts and a Wasmtime runtime with no host imports/WASI, deterministic integer-only ABI v1, fuel/memory/I/O/deadline limits, and bounded indeterminate failure behavior.
- `Certael.Coordinator`, exclusive regional leases, monotonically increasing fencing epochs, signed single-use 60-second region-transfer grants, forced-failover auditing, and fresh-session rebinding requirements.

### Changed

- PostgreSQL remains authoritative; Redis is limited to real-time admission/windows, JetStream is replayable transport, and ClickHouse is a disposable analytics projection.
- New analytical protections default to signed shadow/canary rollout before enforcement.
- Default retention is bounded to 30 days for raw events, 90 days for derived economy analytics, and 180 days for retained case metadata.

### Compatibility

- Action protocol v1 and existing engine clients remain valid.
- Database changes are additive migrations `017` through `020`; the coordinator uses a separate control database.
- Agent `v0.3.0-alpha.3` remains the recommended compatible Agent release.

### Security boundary

- Certael still has no permanent-ban capability. Automated analysis creates explainable findings; signed policy thresholds open cases; operators approve only bounded actions. Game state, bans, appeals, and external moderation remain owned by the integrating game.

[0.4.0-alpha.1]: https://github.com/violetweather/Certael/compare/v0.3.0-alpha.2...v0.4.0-alpha.1
