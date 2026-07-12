# Security policy

## Supported versions

Certael is pre-1.0. Only the latest default-branch revision and newest published
pre-release receive security fixes. A stable support window will be published
before 1.0.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting for the
canonical repository. If unavailable, privately contact the repository owner and
request a secure channel.

Include the affected revision, component, prerequisites, impact, and a minimal
reproduction. Remove player data, credentials, and unnecessary weaponized
payloads. We target acknowledgement within 3 business days and an initial
assessment within 10 business days. These are response targets, not a bounty.

## Safe harbor

Good-faith research against systems and accounts you own, performed without
privacy violations, disruption, persistence, extortion, or access to other
users' data, will not be treated as malicious. Third-party game integrations
require that operator's separate authorization.

## Design invariants

1. Client claims never authorize persistent game-state mutation.
2. No production secret is embedded in a client binary.
3. Tickets are short-lived, audience-bound, proof-of-possession-bound, and single-use.
4. Duplicate action IDs return the original authoritative result.
5. Integrity or behavioral telemetry alone cannot punish an account.
6. The integrating game owns account enforcement and appeals.

Read [the normative security contract](docs/security-contract.md). A client
signature proves ephemeral-key possession, not honest gameplay.
