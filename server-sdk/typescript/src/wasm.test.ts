import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import type { CertaelNativeAddon } from "./native.js";
import {
  SignedWasmRuleRegistry,
  decodeWasmRuleDecision,
  encodeWasmRuleDecision,
  encodeWasmRuleInput,
  wasmSignaturePayload,
} from "./wasm.js";

test("WASM codecs are canonical and reject duplicate evidence", () => {
  const input = encodeWasmRuleInput({ tenantId: "tenant", gameId: "game",
    environmentId: "prod", ruleId: "economy.velocity", ruleVersion: "1",
    canonicalAction: Uint8Array.of(1), canonicalState: Uint8Array.of(2) });
  assert.equal(input[0], 8);
  const decision = encodeWasmRuleDecision({ outcome: "reject", publicReason: "TOO_FAST",
    boundedRisk: 75, boundedEvidence: { z: "last", a: "first" } });
  assert.deepEqual(decodeWasmRuleDecision(decision), { outcome: "reject",
    publicReason: "TOO_FAST", boundedRisk: 75,
    boundedEvidence: Object.assign(Object.create(null), { a: "first", z: "last" }) });
  const duplicate = Uint8Array.from([...decision, ...decision.slice(-11)]);
  assert.throws(() => decodeWasmRuleDecision(duplicate));
});

test("signed WASM registry binds module, rule, and version and bounds traps", () => {
  const keys = generateKeyPairSync("ed25519");
  const module = Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0);
  const digest = createHash("sha256").update(module).digest();
  const signature = sign(null, wasmSignaturePayload("rule.one", "1", digest), keys.privateKey);
  let trapped = false;
  const addon: CertaelNativeAddon = { certaelNodeAbiVersion: () => 2,
    verifyActionEnvelope: () => { throw new Error("unused"); },
    evaluateWasmRule: (_module, input) => {
      assert.ok(input.byteLength > 0);
      if (trapped) throw new Error("trap");
      return encodeWasmRuleDecision({ outcome: "pass", publicReason: "PASS",
        boundedRisk: 0, boundedEvidence: {} });
    } };
  const registry = new SignedWasmRuleRegistry(new Map([["key-1", keys.publicKey]]), { addon });
  registry.register({ ruleId: "rule.one", version: "1", module, digest,
    keyId: "key-1", signature });
  const input = { tenantId: "tenant", gameId: "game", environmentId: "prod",
    ruleId: "rule.one", ruleVersion: "1", canonicalAction: Uint8Array.of(1),
    canonicalState: new Uint8Array() };
  assert.equal(registry.evaluate(digest, input).outcome, "pass");
  trapped = true;
  assert.deepEqual(registry.evaluate(digest, input), { outcome: "indeterminate",
    publicReason: "WASM_INDETERMINATE", boundedRisk: 0, boundedEvidence: {} });
  assert.equal(registry.evaluate(digest, { ...input, ruleVersion: "2" }).publicReason,
    "WASM_PROFILE_BINDING_MISMATCH");
  assert.throws(() => registry.register({ ruleId: "rule.two", version: "1", module,
    digest, keyId: "key-1", signature }));
});
