# ADR 0002: Canonical binary protocol

Status: Accepted

## Decision

Production protocol v1 uses deterministic binary Protobuf envelopes. JSON is
diagnostic only. Signatures cover separately specified canonical bytes and never
depend on a language serializer.

## Consequences

The pre-1.0 JSON-producing C ABI is replaced. Every language and engine adapter
must pass shared golden vectors before protocol v1 freezes.
