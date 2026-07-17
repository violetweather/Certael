import test from "node:test";
import assert from "node:assert/strict";
import { handleAction, replayDigest, type AuthoritativeTransaction } from "./index.js";

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
      actionId: "action", sequence: 1n, actionType: "trade", request: {}, canonicalEnvelope: envelope }) },
    sessions: { find: async () => ({ tenantId: "t", gameId: "g", environmentId: "prod", sessionId: "session",
      playerSubject: "p", serverId: "s", matchId: "m", bindingDigest: new Uint8Array(32) }) },
    admission: { reserve: async () => "reserved" }, transactions: { begin: async () => transaction },
    execute: async () => ({ response: { gold: 5 }, eventId: "event", eventType: "economy.v1", schemaVersion: 1, payload: Uint8Array.of(5) }) });
  assert.equal(result.outcome, "accepted"); assert.deepEqual(calls, ["event", "result", "commit"]);
});
