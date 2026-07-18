# @certael/server

Node 22+ ESM SDK for authoritative Certael game servers. `handleAction()` verifies the native canonical envelope, reserves admission, invokes only the trusted game callback, and stages the accepted result and durable event in one authoritative transaction.

The package includes Core-compatible PostgreSQL session/transaction adapters,
atomic Redis admission, an ABI-checked Rust verifier loader, and exact optional
native packages for Windows x64, Linux x64, and Intel/Apple-silicon macOS. Game
state loading and mutation remain explicit hooks so Certael joins the game's
authoritative database transaction instead of inventing one.

The SDK also includes signed sandboxed-WASM evaluation and authoritative
Steam, EOS, PlayFab, and Agones provider adapters. Steam uses its official
publisher Web API; the other adapters accept only results returned by the
integrating game's official server SDK/client and never normalized client claims.

See the [complete TypeScript server SDK guide](../../docs/typescript-server-sdk.md)
for installation, native verifier wiring, store contracts, an authoritative
action example, deployment, and verification requirements.
