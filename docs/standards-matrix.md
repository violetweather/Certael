# Security standards matrix

This matrix records intended evidence. An incomplete row is not a conformance claim.

| Baseline | Required evidence | 1.0 gate |
|---|---|---|
| NIST SSDF 1.1 PO | requirements, ADRs, protected review, threat model | Required |
| NIST SSDF 1.1 PS | signed artifacts, SBOM, provenance, verification | Required |
| NIST SSDF 1.1 PW | review, tests, fuzzing, dependency/static analysis | Required |
| NIST SSDF 1.1 RV | private reporting, triage, remediation, disclosure | Required |
| OWASP ASVS 5.0 L2 | backend authentication, validation, logging, data tests | Required |
| OWASP ASVS selected L3 | crypto, admin, tenant isolation, key lifecycle | Required |
| SLSA Build L3 v1.2 | isolated hosted build and signed provenance | Required |
| OpenSSF | Scorecard, pinned actions, updates, branch policy | Required |
| SPDX/CycloneDX | source and binary SBOM for every release | Required |
| ISO 29147/30111 style | disclosure and vulnerability response procedure | Required |

Before 1.0, each row will link to specific tests, workflows, artifacts, and audit
records and an external reviewer will validate the matrix.
