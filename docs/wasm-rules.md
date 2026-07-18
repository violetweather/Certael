# Sandboxed WASM rules

Certael ABI-v1 rules are optional, signed, server-only WebAssembly modules. They can return `Pass`, `Reject`, or `Indeterminate`, plus a bounded risk score and up to 64 small evidence entries. A rule cannot mutate game or Certael state.

The host runtime provides no WASI, imports, filesystem, network, clock, randomness, or other host API. It rejects floating point, SIMD, threads, shared memory, and unsupported WebAssembly proposals. Default hard ceilings are a 4 MiB module, 16 MiB memory, 1 MiB canonical input, 64 KiB canonical output, 10 million fuel, and a 10 ms deadline. A trap, timeout, invalid module, resource exhaustion, or malformed output becomes the public `WASM_INDETERMINATE` result.

## Authoring a Rust rule

Use `runtime/certael-wasm-guest`, which is a `no_std` ABI and canonical-Protobuf helper. The reference rule is in `samples/wasm-rules/repeated-reward`.

```rust
use certael_wasm_guest::{decode_input, Decision, Outcome};

fn evaluate(encoded: &[u8]) -> Decision<'static> {
    let Ok(input) = decode_input(encoded) else {
        return Decision { outcome: Outcome::Indeterminate,
            public_reason: "INVALID_INPUT", bounded_risk: 0, evidence: &[] };
    };
    let _trusted_action = input.canonical_action;
    Decision { outcome: Outcome::Pass, public_reason: "PASS",
        bounded_risk: 0, evidence: &[] }
}

certael_wasm_guest::export_rule!(evaluate, 1024);
```

Build a guest with the pinned toolchain:

```text
rustup target add wasm32-unknown-unknown
cargo build --locked --release --target wasm32-unknown-unknown \
  -p certael-reference-repeated-reward-rule
```

The release archive includes the guest SDK source, schema, and compiled reference module. Sign a module digest with the configured offline Ed25519 WASM signing key and bind that digest, rule ID, and version into the staged protection profile before registration. The same signature payload and canonical codecs are implemented by .NET and `@certael/server`.

## Runtime integrations

- .NET loads a pinned absolute `certael-wasm` native library through `NativeWasmRuleRuntime`.
- Node 22+ loads the platform `@certael/server-*` package. `SignedWasmRuleRegistry` verifies the Ed25519 signature and digest before invoking the native runtime.
- Guest output never directly performs a game mutation. The authoritative game callback decides and commits mutations through the normal Certael transaction boundary.
