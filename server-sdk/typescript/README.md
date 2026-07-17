# @certael/server

Node 22+ ESM SDK for authoritative Certael game servers. `handleAction()` verifies the native canonical envelope, reserves admission, invokes only the trusted game callback, and stages the accepted result and durable event in one authoritative transaction.

Supply production `SessionStore`, `AdmissionStore`, and `AuthoritativeTransactionFactory` implementations backed by the same PostgreSQL/Redis infrastructure as the game server. The native package is selected by platform and exposes Core's Rust verifier.
