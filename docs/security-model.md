# Security model

## Boundary

The player controls the client machine. Assume they can inspect source code,
patch branches, suppress SDK calls, forge calls, extract in-memory keys, alter
time, and replace the engine adapter. Certael therefore treats all client data
as untrusted, even when it is encrypted or signed.

The authoritative game server owns persistent state and is the only component
allowed to commit gameplay mutations. Certael protects the request path,
evaluates reusable and game-specific rules, records evidence, and recommends
enforcement. It does not turn the client into a trusted authority.

## Required action flow

1. The client submits typed intent through existing game networking.
2. The server validates session, action ID, sequence, schema, rate, and replay.
3. Rules evaluate the request against authoritative state.
4. The server atomically commits an accepted mutation.
5. The server records an authoritative outcome after commit.
6. Duplicate action IDs return the original result without repeating mutation.

## Cryptography

TLS protects transport. Game servers use mTLS and short-lived OAuth credentials.
Bootstrap tickets expire after 60 seconds, are single-use, and are bound to an
ephemeral client public key, game, environment, player, match, server, and build.
Proof of possession prevents basic ticket replay but is not evidence that an
action is legitimate.

## Enforcement

Certael can reject an individual action and recommend increased sampling,
restriction, kick, temporary suspension, or manual review. The integrating game
owns final account enforcement. Client integrity evidence alone cannot justify
a permanent ban.
