# Certael documentation

This documentation follows the path an integrating game team should take. Begin
with the trust boundary, run the local stack, integrate one authoritative action,
then add engine adapters and game-specific rules.

## Integrator path

1. Read the [security model](security-model.md) and [normative security contract](security-contract.md).
2. [Install a verified prebuilt package](installing-prebuilt.md), or use the source-build path for contributors.
3. Complete the [secure quickstart](getting-started.md).
4. Implement the full [session and action authorization flow](authorization.md).
5. Add the relevant [engine adapter](engine-support.md).
6. Encode invariants using [custom game rules](rules.md).
7. Configure the reusable [protection modules](protections.md).
8. Complete the [production operations checklist](operations.md).

## Reference

| Guide | Audience | Covers |
|---|---|---|
| [Security model](security-model.md) | security and gameplay engineers | boundaries, threats, enforcement limits |
| [Security contract](security-contract.md) | integrators and auditors | normative guarantees, exclusions, and failure rules |
| [Quickstart](getting-started.md) | backend engineers | local stack, builds, first integration |
| [Prebuilt installation](installing-prebuilt.md) | game developers | release downloads, verification, and engine installation |
| [Authorization](authorization.md) | networking and backend engineers | bootstrap, binding, proofs, action handling |
| [Native ABI](native-api.md) | native and engine engineers | C ownership, buffer rules, client runtime, and server verifier |
| [Engine support](engine-support.md) | client engineers | Godot, Unity, Unreal installation and calls |
| [Rules](rules.md) | gameplay and security engineers | YAML packs, callbacks, signing, rollout |
| [Protections](protections.md) | gameplay and security engineers | rate, movement, visibility, economy, behavior, integrity |
| [Operations](operations.md) | platform and SRE teams | identity, keys, persistence, rollout, privacy |
| [Incident response](incident-response.md) | operators and security teams | containment, recovery, and disclosure runbooks |
| [Release process](releasing.md) | maintainers | signed pre-release artifacts and provenance |
| [Troubleshooting](troubleshooting.md) | all integrators | common setup and runtime failures |
| [Verification](testing.md) | contributors and auditors | local, fuzz, load, persistence, and engine tests |
| [Acceptance status](acceptance-status.md) | evaluators | verified and outstanding criteria |
| [Standards matrix](standards-matrix.md) | maintainers and auditors | SSDF, ASVS, SLSA, OpenSSF, SBOM, and disclosure evidence gates |

Architecture decisions are recorded under [`docs/adr`](adr/). They explain the
locked trust boundary and canonical protocol decision; changing either requires
a new superseding ADR and compatibility/security review.

## Non-negotiable integration rule

Never grant an item, spend currency, record a win, move an authoritative entity,
or change progression because the client called Certael successfully. Client SDK
success only means a request envelope was created. The game server must decode
it, authorize the session, evaluate trusted state, and commit the mutation.
