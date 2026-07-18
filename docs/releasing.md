# Release process

Certael remains pre-1.0. Version tags trigger clean native builds for Windows
MSVC, Linux x64, and macOS arm64/x64; managed and TypeScript packages; engine
adapters; installer-ready component ZIPs; SBOMs; provenance attestations;
checksums; and multi-architecture API, event-worker, analytics-worker, console,
and coordinator containers.

The release repository must configure `CERTAEL_SUITE_SIGNING_KEY_BASE64` as an
encrypted Actions secret containing one raw 32-byte Ed25519 private key encoded
with Base64, and `CERTAEL_SUITE_SIGNING_KEY_ID` as a repository variable naming
the corresponding active public key in `certael-release-keys.json`. Production
key generation, custody, rotation, revocation, expiry, and recovery require the
release-key ceremony; never use `suite generate-development-key` for a stable
release.

Before tagging, all required checks must pass on the exact commit. Create a
signed tag and push it:

```bash
git tag -s v0.4.0-alpha.2 -m "Certael v0.4.0-alpha.2"
git push origin v0.4.0-alpha.2
```

The workflow publishes a GitHub pre-release. Stable `v1.*` promotion remains
forbidden until engine conformance, platform code signing, load tests, and
external audit gates pass. A canonical Ed25519 envelope binds the suite manifest
to exact component archives, runtime identifiers, dependencies, sizes, and
SHA-256 digests. GitHub attestations and keyless Sigstore bundles add build
provenance for every release file and all five containers. These controls do not
replace Windows Authenticode, NuGet package signing, or Apple notarization.

The first `v0.1.0-alpha.1` packaging attempt exposed release-only failures and did
not publish a GitHub pre-release. Never move or reuse a failed release tag. Fix
the pipeline on a protected branch, verify it, and issue the next version tag.
Consumers should follow the [prebuilt installation guide](installing-prebuilt.md).
