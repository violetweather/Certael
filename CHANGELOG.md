# Changelog

All notable changes to Certael Core are documented here. Certael follows semantic versioning for public contracts; prerelease APIs may evolve only through explicit versioned contracts and feature flags.

## [0.4.0-alpha.2] - 2026-07-18

### Added

- A managed suite installer foundation with a verbose CLI, signed suite definitions, resumable component installation, prerequisite and port diagnostics, rollback, support-bundle redaction, release Compose assembly, and a native desktop installer UI.
- Complete Unreal Engine Blueprint surfaces for protected actions, session state, Agent challenge/report flow, bounded errors, asynchronous nodes, and game-thread-safe delegates.
- Case metadata definitions and editable metadata values, game-scoped case categories, metadata-aware evidence/case search, rule and signal filtering, deterministic sorting, and cursor-backed case pagination.
- Console settings for case categories and metadata schemas, with permission checks, optimistic concurrency, mandatory audit reasons, loading/empty/error states, responsive layouts, and keyboard operation.
- Economy analysis workers and PostgreSQL/Redis/ClickHouse projections for signed profiles, exact finding receipts, relationship windows, and deterministic replay.
- A regional continuity supervisor that renews leases, stops protected admission on expiry, redeems single-use transfer grants, and rebinds fresh Core and Agent sessions.

### Changed

- Steam, EOS, PlayFab, and Agones adapters now use bounded provider telemetry, authoritative identity/server verification, normalized errors, and explicit outage behavior.
- `@certael/server` now includes platform provider adapters, PostgreSQL and Redis stores, native verifier loading, WASM execution, golden parity coverage, and typed lifecycle helpers.
- The evidence, economy, relationship, WASM, platform-proof, and regional APIs now expose deployable persistence and endpoint implementations rather than contract-only scaffolding.
- The authenticated console keeps dense investigation workflows finite and navigable while retaining the approved Impeccable forensic design system and WCAG 2.2 AA behavior.

### Security

- The coordinator requires mTLS, validates production client CAs, supports an emergency failover certificate allowlist, and preserves exclusive fenced ownership through PostgreSQL leases.
- Platform proof replay protection is shared through Redis, while identity assertions remain explicitly distinct from nonce-bound device attestation.
- Installer logs are verbose but redact credentials, tokens, private keys, and sensitive connection-string values from support bundles.

### Compatibility

- Action protocol v1 and existing engine clients remain valid.
- Database changes are additive through migration `025`; coordinator migrations remain isolated in its control database.
- Agent `v0.4.0-alpha.1` is the recommended compatible Agent release and is pinned by immutable source commit in release artifacts.

### Fixed

- Refreshed the immutable .NET 10 SDK, ASP.NET, and runtime container manifest pins so every multi-architecture release image resolves from Microsoft Container Registry.

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

[0.4.0-alpha.2]: https://github.com/violetweather/Certael/compare/v0.4.0-alpha.1...v0.4.0-alpha.2
[0.4.0-alpha.1]: https://github.com/violetweather/Certael/compare/v0.3.0-alpha.2...v0.4.0-alpha.1
