import test from "node:test";
import assert from "node:assert/strict";
import { CertaelApiClient, CertaelApiError, createNativeVerifier, handleAction,
  replayDigest, sessionBindingDigest,
  type AuthoritativeTransaction, type CertaelNativeAddon, type SessionBinding } from "./index.js";

const bindingWithoutDigest = {
  tenantId: "tenant-a", gameId: "game-a", environmentId: "prod", sessionId: "session-1",
  playerSubject: "player-1", serverId: "server-1", matchId: "match-1", buildId: "build-1",
  protectionProfileId: "profile-1", signingKeyId: "key-1",
  ephemeralPublicKey: new Uint8Array(32), protocolMinimum: 1, protocolMaximum: 2,
  minimumSequence: 1n, maximumSequence: 100n,
  expiresAt: new Date("2030-01-01T00:00:00Z"),
};

function trustedBinding(): SessionBinding {
  return { ...bindingWithoutDigest, bindingDigest: sessionBindingDigest(bindingWithoutDigest) };
}

test("replay digests are deterministic and length framed", () => {
  assert.deepEqual(replayDigest(Uint8Array.of(1), Uint8Array.of(2)), replayDigest(Uint8Array.of(1), Uint8Array.of(2)));
  assert.notDeepEqual(replayDigest(Uint8Array.of(1, 2)), replayDigest(Uint8Array.of(1), Uint8Array.of(2)));
});

test("handleAction stages event and result before one commit", async () => {
  const envelope = Uint8Array.of(1, 2, 3); const calls: string[] = [];
  const transaction: AuthoritativeTransaction<{ gold: number }, { gold: number }> = {
    state: { gold: 4 }, revision: 9n,
    async stageResult() { calls.push("result"); }, async stageEvent() { calls.push("event"); },
    async commit() { calls.push("commit"); return 10n; }, async rollback() { calls.push("rollback"); }
  };
  const result = await handleAction({ envelope, sessionId: "session", verifier: { verify: () => ({
      actionId: "22222222-2222-4222-8222-222222222222", sequence: 1n,
      actionType: "trade", request: {}, canonicalEnvelope: envelope }) },
    sessions: { find: async () => ({ ...trustedBinding(), sessionId: "session",
      bindingDigest: sessionBindingDigest({ ...bindingWithoutDigest, sessionId: "session" }) }) },
    admission: { reserve: async () => "reserved" }, transactions: { begin: async () => transaction },
    execute: async () => ({ response: { gold: 5 },
      eventId: "33333333-3333-4333-8333-333333333333", eventType: "economy.v1",
      schemaVersion: 1, payload: Uint8Array.of(5), additionalEvents: [{
        eventId: "44444444-4444-4444-8444-444444444444", eventType: "relationship.v1",
        schemaVersion: 1, payload: Uint8Array.of(6) }] }) });
  assert.equal(result.outcome, "accepted");
  assert.deepEqual(calls, ["event", "event", "result", "commit"]);
});

test("session binding digest matches the Core golden vector", () => {
  assert.equal(Buffer.from(sessionBindingDigest(bindingWithoutDigest)).toString("hex"),
    "7a3136b6898ec120c6810a87ad1cdf73cf2ef2b633710c68983ff9f15988554c");
});

test("native verifier checks ABI, binding, and decodes only verified payload", async () => {
  const binding = trustedBinding();
  const addon: CertaelNativeAddon = {
    certaelNodeAbiVersion: () => 2,
    evaluateWasmRule: () => Uint8Array.of(),
    verifyActionEnvelope: (_input, sessionId, digest, publicKey, minimum, maximum) => {
      assert.equal(sessionId, binding.sessionId);
      assert.deepEqual(digest, binding.bindingDigest);
      assert.deepEqual(publicKey, binding.ephemeralPublicKey);
      assert.equal(minimum, 1); assert.equal(maximum, 2);
      return { actionId: "11111111-1111-4111-8111-111111111111", sessionId,
        sequence: 4n, actionType: "inventory.craft", requestSchema: "game.Craft.v1",
        schemaVersion: 1, protocolMajor: 1, protocolMinor: 0,
        payload: Uint8Array.of(7), signedDigest: new Uint8Array(32) };
    },
  };
  const verifier = createNativeVerifier({ addon, decodeRequest: (payload, context) => {
    assert.deepEqual(payload, Uint8Array.of(7));
    assert.equal(context.requestSchema, "game.Craft.v1");
    return { quantity: payload[0]! };
  } });
  const envelope = Uint8Array.of(1, 2, 3);
  const verified = await verifier.verify(envelope, binding);
  assert.deepEqual(verified.request, { quantity: 7 });
  assert.deepEqual(verified.canonicalEnvelope, envelope);
  assert.throws(() => createNativeVerifier({ addon: { ...addon,
    certaelNodeAbiVersion: () => 1 }, decodeRequest: () => ({}) }), /ABI/);
});

test("handleAction rejects inconsistent trusted binding before native verification", async () => {
  const binding = trustedBinding();
  binding.bindingDigest[0] = binding.bindingDigest[0]! ^ 1;
  let verified = false;
  const result = await handleAction({ envelope: Uint8Array.of(1), sessionId: binding.sessionId,
    verifier: { verify: () => { verified = true; throw new Error("must not run"); } },
    sessions: { find: async () => binding }, admission: { reserve: async () => "reserved" },
    transactions: { begin: async () => { throw new Error("must not begin"); } },
    execute: async () => { throw new Error("must not execute"); },
    clock: () => new Date("2029-01-01T00:00:00Z") });
  assert.deepEqual(result, { outcome: "rejected", publicReason: "INVALID_SESSION_BINDING" });
  assert.equal(verified, false);
});

test("Core client uses versioned session routes and bounded errors", async () => {
  const requests: { url: string; init?: RequestInit }[] = [];
  const client = new CertaelApiClient(new URL("https://core.example/"),
    (async (input, init) => {
      requests.push(init === undefined ? { url: input.toString() }
        : { url: input.toString(), init });
      return new Response('{"claims":"AQ==","signature":"Ag==","keyId":"key-1"}', {
        status: 200, headers: { "content-type": "application/json" },
      });
    }) as typeof fetch);
  assert.deepEqual(await client.issueTicket({ tenantId: "tenant", gameId: "game",
    environmentId: "prod", playerSubject: "player", matchId: "match",
    serverId: "server", buildId: "build", protectionProfile: "profile",
    ephemeralPublicKey: "AA==" }),
    { claims: "AQ==", signature: "Ag==", keyId: "key-1" });
  assert.equal(requests[0]!.url, "https://core.example/v1/sessions/tickets");
  assert.equal(requests[0]!.init?.method, "POST");

  const failing = new CertaelApiClient(new URL("https://core.example/"),
    (async () => new Response('{"reason":"NOT_AUTHORIZED"}', { status: 403 })) as typeof fetch);
  await assert.rejects(failing.getCase("case-1", new URLSearchParams({
    tenantId: "tenant", environmentId: "prod" })),
    (error: unknown) => error instanceof CertaelApiError
      && error.status === 403 && error.message === "NOT_AUTHORIZED");
});

test("Core client sends Agent protocol as bounded binary without redirects", async () => {
  let observed: { url: string; init?: RequestInit } | undefined;
  const client = new CertaelApiClient(new URL("https://core.example/"),
    (async (input, init) => {
      observed = init === undefined ? { url: input.toString() }
        : { url: input.toString(), init };
      return new Response(Uint8Array.of(9, 8, 7), { status: 200,
        headers: { "content-type": "application/x-protobuf" } });
    }) as typeof fetch, { authorization: "Bearer test" });
  assert.deepEqual(await client.createAgentSession(Uint8Array.of(1, 2, 3)),
    Uint8Array.of(9, 8, 7));
  assert.equal(observed?.url, "https://core.example/v1/agent/sessions");
  assert.equal(observed?.init?.redirect, "error");
  const headers = new Headers(observed?.init?.headers);
  assert.equal(headers.get("content-type"), "application/x-protobuf");
  assert.equal(headers.get("authorization"), "Bearer test");
  assert.deepEqual(new Uint8Array(observed?.init?.body as ArrayBufferLike),
    Uint8Array.of(1, 2, 3));
});
