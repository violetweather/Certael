# Verification guide

## Fast local checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
dotnet test Certael.slnx --warnaserror
```

Build the release native library and C ABI smoke test on the host platform before
changing engine adapters. The nightly workflow fuzzes the strict action-envelope
decoder. Deterministic .NET malformed-input corpora exercise both action and
ticket decoders and fail if an unexpected exception type escapes. Corpus files
that reproduce a bug must be retained as permanent regression tests.

## Protocol load harness

```bash
cargo run --release -p certael-load -- --sessions 100000 --actions-per-session 10
```

This measures local canonical encode/decode/sign/verify throughput only. It does
not satisfy the distributed 100,000-player acceptance gate. Production evidence
must also include PostgreSQL, Redis, API replicas, network latency, failover,
30-minute sustained load, a 2x burst, and a 24-hour soak with published topology.

Partial local result (not an acceptance result): on 2026-07-12 an Apple M4 with
16 GiB RAM running macOS 15.7.7 processed one signed/verified action for each of
100,000 generated sessions in 10.71 seconds (9,339 actions/second). This run had
no network, API replicas, PostgreSQL, Redis, game callbacks, sustained window,
burst, failover, or soak, so the 100,000-session/25,000-admission production gate
remains **not verified**.

## Persistence integration

Set `CERTAEL_TEST_POSTGRES` and `CERTAEL_TEST_REDIS`, then run tests with
`Category=Integration`. Use disposable infrastructure. Tests must cover multiple
API replicas, ticket single-use, tenant RLS, action idempotency, rollback, and
outbox delivery.

On 2026-07-12, the three current integration tests passed locally against
disposable PostgreSQL 17 and Redis 8 containers. The RLS test switches to a
`NOSUPERUSER NOBYPASSRLS` role and verifies both hidden cross-tenant reads and a
denied cross-tenant write. This is useful implementation evidence, but it is not
a substitute for protected CI, failover, or multi-replica testing.

## Engine conformance

Each certified engine build must bootstrap a session, match the shared protocol
vector, send a valid action, reject a tampered action, expire/revoke a session,
package a player build, and fail clearly when its real native library is absent.
