# Certael suite release keys

`certael-release-keys.json` is the public trust store used to verify canonical
suite manifests. It contains no private key material.

Initial active key:

- Key ID: `certael-suite-2026-01`
- Ed25519 public-key SHA-256:
  `2ff149f4bf79ce88ba0478ce3dec26e0ede5ee53a2b8b92baef6ccdef43ba78f`
- Valid through: 2028-07-15 23:59:59 UTC

Do not establish trust by downloading a manifest and an unverified replacement
trust store from the same potentially compromised location. Use the copy bundled
with a previously verified Certael installer/CLI release, verify the GitHub
attestation and Sigstore bundle, and compare the public-key fingerprint through
an independently authenticated project channel.

Rotation requires an overlap release containing both the active and successor
public keys before the successor signs a suite manifest. Revocation sets the old
record's `revoked` field to `true` and requires a security release through an
already trusted path. Expired, not-yet-valid, unknown, or revoked keys are
rejected even when the manifest signature is mathematically valid.

The corresponding private key exists only as the encrypted GitHub Actions secret
`CERTAEL_SUITE_SIGNING_KEY_BASE64`. The release workflow selects it through the
repository variable `CERTAEL_SUITE_SIGNING_KEY_ID`; it never writes the private
key into a release artifact, cache, build log, SBOM, or repository file.
