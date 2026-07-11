# System threat model

## Assets

- Authoritative game state
- Player accounts and pseudonymous identifiers
- Session and service credentials
- Rule packs and build manifests
- Evidence and enforcement history
- Release signing keys

## Primary threats

| Threat | Boundary | Required control |
|---|---|---|
| Forged gameplay result | client/server | accept intent only; server commits state |
| Replayed action | network/server | session binding, sequence, action ID, idempotency |
| Ticket theft | bootstrap | 60-second TTL, one-time redemption, key binding |
| Cross-match substitution | session | bind ticket and action to match and server |
| Double spend | game state | transaction and authoritative revision |
| Client telemetry fabrication | client/Certael | provenance labels; corroboration required |
| Rule compromise | control plane | signing, approval, canary, rollback, audit |
| Tenant escape | backend | tenant-scoped identities and storage authorization |
| Update compromise | supply chain | signatures, provenance, rollback protection |
| Evidence privacy breach | backend | minimization, redaction, retention, access audit |

## Trust assumptions

Dedicated game servers and Certael backend workloads are operated in controlled
environments. Peer hosts are not trusted and receive reduced-assurance status.
