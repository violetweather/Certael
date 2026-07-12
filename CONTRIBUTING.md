# Contributing to Certael

Certael is security-sensitive infrastructure. Every change must preserve
`docs/security-contract.md` and include tests proportional to risk.

1. Create a branch from `main`.
2. Make a focused change with tests and documentation.
3. Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, and `dotnet test Certael.slnx`.
4. Open a pull request and resolve all conversations.

Do not commit credentials, private keys, player data, build output, generated
IDE state, or proprietary assets. Cryptographic, protocol, unsafe-code,
authorization, tenant-boundary, parser, and release changes require explicit
security review.
