import test from "node:test";
import assert from "node:assert/strict";
import { PostgresAuthoritativeTransactionFactory, PostgresSessionStore,
  RedisAdmissionStore, sessionBindingDigest, type PostgresClient,
  type PostgresQueryResult, type SessionBinding } from "./index.js";

class FakePostgresClient implements PostgresClient {
  readonly calls: { text: string; values?: readonly unknown[] }[] = [];
  released = false;
  constructor(private readonly responder: (text: string) => PostgresQueryResult =
    () => ({ rows: [], rowCount: 1 })) {}
  async query<TRow = Record<string, unknown>>(text: string,
    values?: readonly unknown[]): Promise<PostgresQueryResult<TRow>> {
    this.calls.push(values === undefined ? { text } : { text, values });
    return this.responder(text) as PostgresQueryResult<TRow>;
  }
  release() { this.released = true; }
}

const row = {
  session_id: "session-1", tenant_id: "tenant-a", game_id: "game-a",
  environment_id: "prod", player_subject: "player-1", match_id: "match-1",
  authoritative_server_id: "server-1", build_id: "build-1",
  expires_at: "2030-01-01T00:00:00Z", absolute_expires_at: null, revoked_at: null,
  ephemeral_public_key: new Uint8Array(32), signing_key_id: "key-1",
  protection_profile_id: "profile-1", protocol_minimum: 1, protocol_maximum: 2,
  minimum_sequence: "1", maximum_sequence: "100",
};

test("PostgresSessionStore scopes RLS and computes the trusted binding", async () => {
  const client = new FakePostgresClient(text => text.includes("FROM certael_sessions")
    ? { rows: [row], rowCount: 1 } : { rows: [], rowCount: 1 });
  const store = new PostgresSessionStore({ connect: async () => client }, "tenant-a", "prod",
    () => new Date("2029-01-01T00:00:00Z"));
  const binding = await store.find("session-1");
  assert.ok(binding);
  assert.deepEqual(binding.bindingDigest, sessionBindingDigest(binding));
  assert.equal(binding.minimumSequence, 1n); assert.equal(binding.maximumSequence, 100n);
  assert.match(client.calls[1]!.text, /set_config/);
  assert.deepEqual(client.calls[1]!.values, ["tenant-a"]);
  assert.equal(client.calls.at(-1)!.text, "COMMIT");
  assert.equal(client.released, true);
});

test("RedisAdmissionStore invokes one bounded atomic script", async () => {
  const calls: unknown[] = [];
  const responses = [1, 2, 3];
  const firstAction = "11111111-1111-4111-8111-111111111111";
  const secondAction = "22222222-2222-4222-8222-222222222222";
  const store = new RedisAdmissionStore({ eval: async (script, options) => {
    calls.push({ script, options }); return responses.shift();
  } }, "tenant-a", 600, 50);
  assert.equal(await store.reserve("session-1", firstAction, 9n), "reserved");
  assert.equal(await store.reserve("session-1", firstAction, 9n), "duplicate");
  assert.equal(await store.reserve("session-1", secondAction, 8n), "replay");
  const first = calls[0] as { script: string; options: { keys: string[]; arguments: string[] } };
  assert.match(first.script, /redis\.call\('HSET'/);
  assert.deepEqual(first.options.keys, ["certael:admission:tenant-a:{session-1}"]);
  assert.deepEqual(first.options.arguments, [firstAction, "9", "600", "50"]);
});

function binding(): SessionBinding {
  const source = { tenantId: "tenant-a", gameId: "game-a", environmentId: "prod",
    sessionId: "session-1", playerSubject: "player-1", serverId: "server-1",
    matchId: "match-1", buildId: "build-1", protectionProfileId: "profile-1",
    signingKeyId: "key-1", ephemeralPublicKey: new Uint8Array(32),
    protocolMinimum: 1, protocolMaximum: 2, minimumSequence: 1n, maximumSequence: 100n,
    expiresAt: new Date("2030-01-01T00:00:00Z") };
  return { ...source, bindingDigest: sessionBindingDigest(source) };
}

test("Postgres transaction stages mutation, result, and outbox before one commit", async () => {
  const client = new FakePostgresClient();
  const calls: string[] = [];
  const factory = new PostgresAuthoritativeTransactionFactory({
    pool: { connect: async () => client }, tenantId: "tenant-a", responseType: "craft.v1",
    loadState: async () => ({ state: { gold: 4 }, revision: 9n }),
    commitGameMutation: async () => { calls.push("mutation"); return 10n; },
    serializeResult: result => ({ outcome: result.outcome }),
    clock: () => new Date("2029-01-01T00:00:00Z"),
  });
  const transaction = await factory.begin(binding());
  await transaction.stageEvent("11111111-1111-4111-8111-111111111111", "economy.craft.v1",
    1, Uint8Array.of(1));
  await transaction.stageEvent("33333333-3333-4333-8333-333333333333", "relationship.v1",
    1, Uint8Array.of(2));
  await transaction.stageResult("22222222-2222-4222-8222-222222222222",
    { outcome: "accepted", response: { gold: 5 }, revision: 10n,
      replayDigest: new Uint8Array(32) });
  assert.equal(await transaction.commit(), 10n);
  assert.deepEqual(calls, ["mutation"]);
  assert.equal(client.calls.filter(value => value.text.trim() === "COMMIT").length, 1);
  assert.ok(client.calls.some(value => value.text.includes("certael_action_results")));
  assert.ok(client.calls.some(value => value.text.includes("certael_outbox")));
  assert.equal(client.calls.filter(value => value.text.includes("INSERT INTO certael_outbox")).length, 2);
  assert.equal(client.released, true);
});

test("Postgres transaction rolls back before commit on revision mismatch", async () => {
  const client = new FakePostgresClient();
  const factory = new PostgresAuthoritativeTransactionFactory({
    pool: { connect: async () => client }, tenantId: "tenant-a", responseType: "craft.v1",
    loadState: async () => ({ state: {}, revision: 1n }),
    commitGameMutation: async () => 3n, serializeResult: () => ({}),
  });
  const transaction = await factory.begin(binding());
  await transaction.stageEvent("11111111-1111-4111-8111-111111111111", "event.v1", 1,
    Uint8Array.of(1));
  await transaction.stageResult("22222222-2222-4222-8222-222222222222",
    { outcome: "rejected", publicReason: "NO" });
  await assert.rejects(transaction.commit(), /advance exactly once/);
  assert.equal(client.calls.at(-1)!.text, "ROLLBACK");
  assert.equal(client.calls.some(value => value.text.includes("certael_outbox")), false);
  assert.equal(client.released, true);
});
