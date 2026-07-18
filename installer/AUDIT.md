# Certael Setup — Impeccable Audit

Date: 2026-07-18
Score: 19/20
P0 findings: 0
P1 findings: 0

## Direction and composition

- The approved calm, precise, technical direction is preserved in a native two-column setup workspace.
- One primary action remains visible in every phase; the numbered rail communicates state without relying on color.
- Signed inputs, project destination, platform, review, progress, result, rollback, and recovery remain distinct operator decisions.
- The design contains no glassmorphism, gradients, decorative security graphics, generic card grid, alarm-heavy treatment, or fake metrics.

## Accessibility and resilience

- Controls retain native keyboard and focus behavior and have explicit automation names where the visual label is separate.
- Verification failures use text plus color, appear adjacent to the operation, and use an assertive accessibility live region.
- The primary action remains visible at the 1060×760 default and 820×620 minimum window sizes.
- Long content scrolls vertically; paths and the redacted technical transcript support overflow without widening the window.
- Cancellation is bounded, mutation is transactional, rollback/recovery outcomes are explicit, and secrets are redacted before display or export.

## Verified states

- Default install selection at 1060×760.
- Missing-input verification failure.
- Minimum 820×620 window.
- Keyboard invocation of the primary verification action through the Windows accessibility tree.
- Release build with warnings treated as errors.
- Runtime `--self-test` without creating or modifying an installation.

## Remaining release operations

- Windows code signing and macOS signing/notarization require release-infrastructure certificates. The release workflow produces digest-addressed artifacts for those downstream signing gates.

No hard-ban pattern remains unresolved.
