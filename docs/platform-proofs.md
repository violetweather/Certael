# Platform identity and attestation

Certael treats platform login and device attestation as different proof classes.

- Steam user tickets and Epic Online Services ID tokens are **identity** proofs. They establish an authoritative vendor account/application binding. Their normalized nonce digest is intentionally empty because those login assertions do not prove device integrity or a Certael nonce.
- An **attestation** provider must use an official vendor mechanism that returns a server-verifiable, nonce-bound assertion. It must verify the signature or certificate chain, application identity, subject, freshness, and nonce before returning `Verified`.

`PlatformProofService` checks the normalized provider, proof kind, subject, application, issued/verified timestamps, claims digest, and nonce digest. Verified attestation nonces are reserved atomically through `IPlatformProofReplayStore`; production deployments use Redis so replay protection is shared across replicas. A reused nonce returns `PLATFORM_PROOF_REPLAY`.

Required versus optional behavior comes from a signed, expiring `PlatformProofPolicyProfile`. When a provider is absent or unavailable, a required policy is unsatisfied and an optional policy reports `OPTIONAL_PROOF_UNAVAILABLE`. A classification, binding, application, freshness, nonce, replay, or malformed-output failure is never treated as optional success.

Steam and EOS packages implement `IPlatformIdentityVerifier`. Certael does not label them as attestation providers. Genuine `IPlatformAttestationVerifier` packages are added only when an official vendor API offers the full server-verifiable nonce contract; integrations must pass the same substitution, freshness, wrong-application, chain failure, timeout, and replay conformance suite.

Platform proof findings are environmental evidence. They can contribute to an explainable finding or manual-review case but cannot independently produce a permanent punishment; Certael has no permanent-ban action.
