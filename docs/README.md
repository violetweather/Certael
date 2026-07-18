# Certael documentation

This documentation follows the path an integrating game team should take. Begin
with the trust boundary, run the local stack, integrate one authoritative action,
then add engine adapters and game-specific rules.

## Integrator path

1. Read the [security model](security-model.md) and [normative security contract](security-contract.md).
2. [Install a verified prebuilt package](installing-prebuilt.md), or use the source-build path for contributors.
3. Use the [suite installer](suite-installer.md) for a signed, transactional full-stack setup.
4. Complete the [secure quickstart](getting-started.md).
5. Implement the full [session and action authorization flow](authorization.md).
6. Integrate the [.NET SDK](getting-started.md#3-reference-the-authoritative-sdk)
   or [TypeScript server SDK](typescript-server-sdk.md) on the authoritative server.
7. Add the relevant [engine adapter](engine-support.md).
8. Encode invariants using [custom game rules](rules.md).
9. Configure the reusable [protection modules](protections.md).
10. Complete the [production operations checklist](operations.md).
11. Deploy the secured [operator console](console-setup.md) when enabling evidence
   and case workflows.
12. Configure the signed [version support and withdrawal policy](compatibility.md).
13. Add [multi-region controlled continuity](multi-region-continuity.md) only
    after region-local protected play is stable.

## Reference

| Guide | Audience | Covers |
|---|---|---|
| [Security model](security-model.md) | security and gameplay engineers | boundaries, threats, enforcement limits |
| [Security contract](security-contract.md) | integrators and auditors | normative guarantees, exclusions, and failure rules |
| [Quickstart](getting-started.md) | backend engineers | local stack, builds, first integration |
| [Prebuilt installation](installing-prebuilt.md) | game developers | release downloads, verification, and engine installation |
| [Suite installer](suite-installer.md) | game developers and platform engineers | signed full-suite install, inspect, repair, update, recovery, uninstall, and deployment bootstrap |
| [Authorization](authorization.md) | networking and backend engineers | bootstrap, binding, proofs, action handling |
| [TypeScript server SDK](typescript-server-sdk.md) | Node.js backend engineers | installation, native verifier, stores, atomic actions, deployment |
| [Native ABI](native-api.md) | native and engine engineers | C ownership, buffer rules, client runtime, and server verifier |
| [Engine support](engine-support.md) | client engineers | Godot, Unity, Unreal installation and calls |
| [Economy and collusion protection](economy-protection.md) | server and security engineers | canonical economy/relationship events, signed rollout, graph findings, and cases |
| [Game-backend integrations](game-backend-integrations.md) | backend and platform engineers | Steam, EOS, PlayFab, Agones identity/server binding and lifecycle |
| [Sandboxed WASM rules](wasm-rules.md) | server and security engineers | signed modules, guest SDK, deterministic limits, and runtime integration |
| [Platform identity and attestation](platform-proofs.md) | identity and security engineers | proof classification, signed policy, freshness, nonce binding, replay, and outages |
| [Multi-region continuity](multi-region-continuity.md) | platform, gameplay, and SRE teams | exclusive leases, fencing epochs, signed transfer grants, mTLS, and failover |
| [Rules](rules.md) | gameplay and security engineers | YAML packs, callbacks, signing, rollout |
| [Protections](protections.md) | gameplay and security engineers | rate, movement, visibility, economy, behavior, integrity |
| [Operations](operations.md) | platform and SRE teams | identity, keys, persistence, rollout, privacy |
| [Operator console](console-setup.md) | security operators and platform teams | local preview, OIDC, mTLS, BFF configuration, hosting, verification |
| [Compatibility](compatibility.md) | release and security operators | supported versions, required updates, withdrawals, and build binding |
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
