# ADR 0001: Prevention-first security boundary

Status: Accepted

## Decision

Certael is self-hosted and prevention-first. Dedicated servers own authoritative
state. Client integrity and behavior are advisory. The game operator owns bans
and appeals. Certael will not ship a kernel driver.

## Consequences

The SDK prioritizes typed intent, authoritative validation, atomic mutation, and
explainable evidence. It does not present possession proofs or user-mode
integrity as proof of honest play.
