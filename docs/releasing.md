# Release process

Certael remains pre-1.0. Tags matching `v0.*` trigger clean native builds for
Windows MSVC, Linux x64, and macOS arm64/x64, a NuGet package, SBOM, provenance
attestations, checksums, and a multi-architecture backend container.

Before tagging, all required checks must pass on the exact commit. Create a
signed tag and push it:

```bash
git tag -s v0.2.0 -m "Certael v0.2.0"
git push origin v0.2.0
```

The workflow publishes a GitHub pre-release. Stable `v1.*` release automation
will remain disabled until engine conformance, platform code signing, load tests,
and external audit gates pass. A GitHub attestation and SHA-256 checksum verify
provenance. The workflow also creates keyless Sigstore bundles for release files
and signs the container by immutable digest; these do not replace Windows
Authenticode, NuGet package signing, or Apple notarization.

As of 2026-07-12, hosted jobs still terminate before their first step, consistent
with the repository's unresolved GitHub Actions billing lock. Do not configure
required checks until at least one run produces real check names, and do not tag
a release from locally built artifacts.
