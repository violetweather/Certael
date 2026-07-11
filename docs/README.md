# Certael documentation

This documentation follows the path an integrating game team should take. Begin
with the trust boundary, run the local stack, integrate one authoritative action,
then add engine adapters and game-specific rules.

## Integrator path

1. Read the [security model](security-model.md).
2. Complete the [secure quickstart](getting-started.md).
3. Implement the full [session and action authorization flow](authorization.md).
4. Add the relevant [engine adapter](engine-support.md).
5. Encode invariants using [custom game rules](rules.md).
6. Configure the reusable [protection modules](protections.md).
7. Complete the [production operations checklist](operations.md).

## Reference

| Guide | Audience | Covers |
|---|---|---|
| [Security model](security-model.md) | security and gameplay engineers | boundaries, threats, enforcement limits |
| [Quickstart](getting-started.md) | backend engineers | local stack, builds, first integration |
| [Authorization](authorization.md) | networking and backend engineers | bootstrap, binding, proofs, action handling |
| [Engine support](engine-support.md) | client engineers | Godot, Unity, Unreal installation and calls |
| [Rules](rules.md) | gameplay and security engineers | YAML packs, callbacks, signing, rollout |
| [Protections](protections.md) | gameplay and security engineers | rate, movement, visibility, economy, behavior, integrity |
| [Operations](operations.md) | platform and SRE teams | identity, keys, persistence, rollout, privacy |
| [Troubleshooting](troubleshooting.md) | all integrators | common setup and runtime failures |
| [Acceptance status](acceptance-status.md) | evaluators | verified and outstanding criteria |

## Non-negotiable integration rule

Never grant an item, spend currency, record a win, move an authoritative entity,
or change progression because the client called Certael successfully. Client SDK
success only means a request envelope was created. The game server must decode
it, authorize the session, evaluate trusted state, and commit the mutation.
