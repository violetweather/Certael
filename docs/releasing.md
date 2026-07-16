# Release process

Certael remains pre-1.0. Tags matching `v0.*` trigger clean native builds for
Windows MSVC, Linux x64, and macOS arm64/x64, a NuGet package, SBOM, provenance
attestations, checksums, and a multi-architecture backend container.

Before tagging, all required checks must pass on the exact commit. Create a
signed tag and push it:

```bash
git tag -s v0.3.0-alpha.1 -m "Certael v0.3.0-alpha.1"
git push origin v0.3.0-alpha.1
```

The workflow publishes a GitHub pre-release. Stable `v1.*` release automation
will remain disabled until engine conformance, platform code signing, load tests,
and external audit gates pass. A GitHub attestation and SHA-256 checksum verify
provenance. The workflow also creates keyless Sigstore bundles for release files
and signs the container by immutable digest; these do not replace Windows
Authenticode, NuGet package signing, or Apple notarization.

The first `v0.1.0-alpha.1` packaging attempt exposed release-only failures and did
not publish a GitHub pre-release. Never move or reuse a failed release tag. Fix
the pipeline on a protected branch, verify it, and issue the next version tag.
Consumers should follow the [prebuilt installation guide](installing-prebuilt.md).
