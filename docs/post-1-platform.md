# Post-1 security platform

Version `0.4.0-alpha.1` is the first deployable post-1 platform release. Every new subsystem is feature flagged and independently deployable.

| Capability | Deployable | Authoritative state | Default mode |
| --- | --- | --- | --- |
| Event/evidence pipeline | Event worker + analytics worker | PostgreSQL outbox/receipts | Enabled transport |
| Cases and investigation | Core API + console BFF + React console | PostgreSQL | Tenant opt-in |
| Economy protection | Analytics worker + server SDK | PostgreSQL ledger | Shadow |
| Collusion analysis | Analytics worker + console | PostgreSQL edges/ClickHouse projection | Shadow |
| Backend integrations | Provider packages | Provider backend + Core sessions | Provider opt-in |
| TypeScript servers | `@certael/server` + native package | Game transaction | Package opt-in |
| WASM rules | `certael-wasm` | Signed module digest/profile | Disabled |
| Platform proofs | Identity/attestation providers | Signed policy | Optional |
| Multi-region continuity | Coordinator + control PostgreSQL | Exclusive fenced lease | Disabled |

## Operational invariants

Accepted gameplay mutations and their canonical events commit in one authoritative transaction. Workers use tenant-scoped RLS and never `BYPASSRLS`. Duplicate delivery is absorbed by event IDs and processing receipts. Analytics can be rebuilt from authoritative data and JetStream replay.

An economy or relationship finding records exact source events, rule and baseline versions, threshold, window, authoritative fields, and replay digest. Findings do not directly create permanent punishment.

Regional gameplay remains local. A destination becomes authoritative only after source release or lease expiry and a successful single-use transfer redemption. The destination then creates fresh Core and Agent sessions; stale epochs cannot commit.
