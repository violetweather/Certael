import type { ActionOutcome, AdmissionStore, AuthoritativeTransaction,
  AuthoritativeTransactionFactory, SessionBinding, SessionStore } from "./index.js";
import { sessionBindingDigest } from "./native.js";

export interface PostgresQueryResult<TRow = Record<string, unknown>> {
  readonly rows: TRow[];
  readonly rowCount?: number | null;
}

export interface PostgresClient {
  query<TRow = Record<string, unknown>>(text: string,
    values?: readonly unknown[]): Promise<PostgresQueryResult<TRow>>;
  release(): void;
}

export interface PostgresPool {
  connect(): Promise<PostgresClient>;
}

interface SessionRow {
  session_id: string; tenant_id: string; game_id: string; environment_id: string;
  player_subject: string; match_id: string; authoritative_server_id: string;
  build_id: string; expires_at: Date | string; absolute_expires_at: Date | string | null;
  revoked_at: Date | string | null; ephemeral_public_key: Uint8Array;
  signing_key_id: string; protection_profile_id: string;
  protocol_minimum: number; protocol_maximum: number;
  minimum_sequence: bigint | number | string; maximum_sequence: bigint | number | string;
}

export class PostgresSessionStore implements SessionStore {
  constructor(private readonly pool: PostgresPool, private readonly tenantId: string,
    private readonly environmentId: string, private readonly clock: () => Date = () => new Date()) {
    validateIdentifier(tenantId, "tenant ID");
    validateIdentifier(environmentId, "environment ID");
  }

  async find(sessionId: string, signal?: AbortSignal): Promise<SessionBinding | undefined> {
    validateIdentifier(sessionId, "session ID");
    signal?.throwIfAborted();
    const client = await this.pool.connect();
    let transaction = false;
    try {
      await client.query("BEGIN"); transaction = true;
      await client.query("SELECT set_config('certael.tenant_id', $1, true)", [this.tenantId]);
      const result = await client.query<SessionRow>(`
        SELECT session_id, tenant_id, game_id, environment_id, player_subject, match_id,
               authoritative_server_id, build_id, expires_at, absolute_expires_at,
               revoked_at, ephemeral_public_key, signing_key_id, protection_profile_id,
               protocol_minimum, protocol_maximum, minimum_sequence, maximum_sequence
        FROM certael_sessions
        WHERE tenant_id = $1 AND environment_id = $2 AND session_id = $3
        LIMIT 1`, [this.tenantId, this.environmentId, sessionId]);
      await client.query("COMMIT"); transaction = false;
      const row = result.rows[0];
      if (row === undefined || row.revoked_at !== null) return undefined;
      const expiresAt = asDate(row.expires_at, "session expiry");
      const absolute = row.absolute_expires_at === null ? undefined
        : asDate(row.absolute_expires_at, "absolute session expiry");
      const now = this.clock().getTime();
      if (expiresAt.getTime() <= now || (absolute !== undefined && absolute.getTime() <= now))
        return undefined;
      const ephemeralPublicKey = asBytes(row.ephemeral_public_key, 32,
        "session ephemeral public key");
      const withoutDigest = {
        tenantId: row.tenant_id, gameId: row.game_id, environmentId: row.environment_id,
        sessionId: row.session_id, playerSubject: row.player_subject,
        serverId: row.authoritative_server_id, matchId: row.match_id, buildId: row.build_id,
        protectionProfileId: row.protection_profile_id, signingKeyId: row.signing_key_id,
        ephemeralPublicKey, protocolMinimum: row.protocol_minimum,
        protocolMaximum: row.protocol_maximum,
        minimumSequence: asBigInt(row.minimum_sequence, "minimum sequence"),
        maximumSequence: asBigInt(row.maximum_sequence, "maximum sequence"), expiresAt,
      };
      return { ...withoutDigest, bindingDigest: sessionBindingDigest(withoutDigest) };
    } catch (error) {
      if (transaction) {
        try { await client.query("ROLLBACK"); } catch { /* preserve original failure */ }
      }
      throw error;
    } finally {
      client.release();
    }
  }
}

export interface RedisEvalClient {
  eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
}

const ADMISSION_SCRIPT = `
local key = KEYS[1]
local action = 'a:' .. ARGV[1]
local sequence = ARGV[2]
local ttl = tonumber(ARGV[3])
local maximum = tonumber(ARGV[4])
if redis.call('HEXISTS', key, action) == 1 then return 2 end
local previous = redis.call('HGET', key, 'sequence')
local function less_or_equal(left, right)
  left = string.gsub(left, '^0+', '')
  right = string.gsub(right, '^0+', '')
  if left == '' then left = '0' end
  if right == '' then right = '0' end
  if string.len(left) ~= string.len(right) then return string.len(left) < string.len(right) end
  return left <= right
end
if previous and less_or_equal(sequence, previous) then return 3 end
if redis.call('HLEN', key) >= maximum + 1 then return 4 end
redis.call('HSET', key, 'sequence', sequence, action, '1')
redis.call('EXPIRE', key, ttl)
return 1`;

export class RedisAdmissionStore implements AdmissionStore {
  private readonly keyPrefix: string;
  constructor(private readonly client: RedisEvalClient, tenantId: string,
    private readonly ttlSeconds = 3600, private readonly maximumActions = 100_000) {
    validateIdentifier(tenantId, "tenant ID");
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86_400
        || !Number.isSafeInteger(maximumActions) || maximumActions < 1
        || maximumActions > 1_000_000)
      throw new Error("Redis admission bounds are invalid");
    this.keyPrefix = `certael:admission:${tenantId}`;
  }

  async reserve(sessionId: string, actionId: string, sequence: bigint,
    signal?: AbortSignal): Promise<"reserved" | "duplicate" | "replay"> {
    validateIdentifier(sessionId, "session ID");
    validateUuid(actionId, "action ID");
    if (sequence < 0n || sequence > 18_446_744_073_709_551_615n)
      throw new Error("Certael action sequence is outside unsigned 64-bit range");
    signal?.throwIfAborted();
    const result = await this.client.eval(ADMISSION_SCRIPT, {
      keys: [`${this.keyPrefix}:{${sessionId}}`],
      arguments: [actionId, sequence.toString(), this.ttlSeconds.toString(),
        this.maximumActions.toString()],
    });
    signal?.throwIfAborted();
    if (result === 1 || result === "1") return "reserved";
    if (result === 2 || result === "2") return "duplicate";
    if (result === 3 || result === "3" || result === 4 || result === "4") return "replay";
    throw new Error("Redis admission script returned an invalid result");
  }
}

export interface PostgresStateSnapshot<TState> {
  readonly state: TState;
  readonly revision: bigint;
}

export interface PostgresTransactionOptions<TState, TResponse> {
  readonly pool: PostgresPool;
  readonly tenantId: string;
  readonly responseType: string;
  readonly loadState: (client: PostgresClient, binding: SessionBinding) =>
    Promise<PostgresStateSnapshot<TState>>;
  readonly commitGameMutation: (client: PostgresClient, binding: SessionBinding,
    state: TState, previousRevision: bigint) => Promise<bigint>;
  readonly serializeResult: (result: ActionOutcome<TResponse>) => unknown;
  readonly clock?: () => Date;
}

export class PostgresAuthoritativeTransactionFactory<TState, TResponse>
implements AuthoritativeTransactionFactory<TState, TResponse> {
  constructor(private readonly options: PostgresTransactionOptions<TState, TResponse>) {
    validateIdentifier(options.tenantId, "tenant ID");
    validateIdentifier(options.responseType, "response type");
  }

  async begin(binding: SessionBinding, signal?: AbortSignal):
  Promise<AuthoritativeTransaction<TState, TResponse>> {
    signal?.throwIfAborted();
    if (binding.tenantId !== this.options.tenantId)
      throw new Error("PostgreSQL transaction tenant does not match the session");
    const client = await this.options.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('certael.tenant_id', $1, true)",
        [this.options.tenantId]);
      const snapshot = await this.options.loadState(client, binding);
      if (snapshot.revision < 0n) throw new Error("Authoritative revision is invalid");
      return new PostgresAuthoritativeTransaction(client, binding, snapshot,
        this.options);
    } catch (error) {
      try { await client.query("ROLLBACK"); } catch { /* preserve original failure */ }
      client.release();
      throw error;
    }
  }
}

class PostgresAuthoritativeTransaction<TState, TResponse>
implements AuthoritativeTransaction<TState, TResponse> {
  readonly state: TState;
  readonly revision: bigint;
  private pendingResult?: { actionId: string; result: ActionOutcome<TResponse> };
  private readonly pendingEvents: { eventId: string; eventType: string;
    schemaVersion: number; payload: Uint8Array }[] = [];
  private completed = false;

  constructor(private readonly client: PostgresClient, private readonly binding: SessionBinding,
    snapshot: PostgresStateSnapshot<TState>,
    private readonly options: PostgresTransactionOptions<TState, TResponse>) {
    this.state = snapshot.state; this.revision = snapshot.revision;
  }

  async stageResult(actionId: string, result: ActionOutcome<TResponse>,
    signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted(); validateUuid(actionId, "action ID");
    if (this.completed || this.pendingResult !== undefined)
      throw new Error("Authoritative result was already staged or transaction completed");
    this.pendingResult = { actionId, result };
  }

  async stageEvent(eventId: string, eventType: string, schemaVersion: number,
    payload: Uint8Array, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted(); validateUuid(eventId, "event ID");
    validateIdentifier(eventType, "event type");
    if (this.completed || this.pendingEvents.length >= 256
        || this.pendingEvents.some(event => event.eventId === eventId)
        || !Number.isInteger(schemaVersion)
        || schemaVersion < 1 || payload.byteLength > 1024 * 1024)
      throw new Error("Authoritative event is invalid or already staged");
    this.pendingEvents.push({ eventId, eventType, schemaVersion,
      payload: Uint8Array.from(payload) });
  }

  async commit(signal?: AbortSignal): Promise<bigint> {
    signal?.throwIfAborted();
    if (this.completed || this.pendingResult === undefined || this.pendingEvents.length === 0)
      throw new Error("Authoritative transaction is incomplete or already completed");
    try {
      const committedRevision = await this.options.commitGameMutation(this.client,
        this.binding, this.state, this.revision);
      if (committedRevision !== this.revision + 1n)
        throw new Error("Committed game revision did not advance exactly once");
      const serialized = JSON.stringify(this.options.serializeResult(this.pendingResult.result));
      if (serialized === undefined || Buffer.byteLength(serialized) > 1024 * 1024)
        throw new Error("Serialized authoritative result is invalid or too large");
      await this.client.query(`
      INSERT INTO certael_action_results
        (tenant_id, session_id, action_id, response_type, result, status)
      VALUES ($1,$2,$3,$4,$5::jsonb,'completed')`, [this.binding.tenantId,
        this.binding.sessionId, this.pendingResult.actionId, this.options.responseType, serialized]);
      for (const event of this.pendingEvents) await this.client.query(`
      INSERT INTO certael_outbox
        (outbox_id, tenant_id, game_id, environment_id, session_id, action_id,
         event_type, schema_version, payload, occurred_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [event.eventId,
        this.binding.tenantId, this.binding.gameId, this.binding.environmentId,
        this.binding.sessionId, this.pendingResult.actionId, event.eventType,
        event.schemaVersion, Buffer.from(event.payload),
        (this.options.clock?.() ?? new Date()).toISOString()]);
      await this.client.query("COMMIT");
      this.completed = true;
      this.client.release();
      return committedRevision;
    } catch (error) {
      try { await this.client.query("ROLLBACK"); }
      finally { this.completed = true; this.client.release(); }
      throw error;
    }
  }

  async rollback(): Promise<void> {
    if (this.completed) return;
    this.completed = true;
    try { await this.client.query("ROLLBACK"); }
    finally { this.client.release(); }
  }
}

function validateIdentifier(value: string, label: string): void {
  if (value.length === 0 || value.length > 128 || !/^[A-Za-z0-9._-]+$/.test(value))
    throw new Error(`Certael ${label} is invalid`);
}

function validateUuid(value: string, label: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value))
    throw new Error(`Certael ${label} is invalid`);
}

function asDate(value: Date | string, label: string): Date {
  const result = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(result.getTime())) throw new Error(`Certael ${label} is invalid`);
  return result;
}

function asBytes(value: Uint8Array, length: number, label: string): Uint8Array {
  const result = Uint8Array.from(value);
  if (result.byteLength !== length) throw new Error(`Certael ${label} is invalid`);
  return result;
}

function asBigInt(value: bigint | number | string, label: string): bigint {
  try {
    const result = typeof value === "bigint" ? value : BigInt(value);
    if (result < 0n || result > 18_446_744_073_709_551_615n)
      throw new Error();
    return result;
  } catch {
    throw new Error(`Certael ${label} is invalid`);
  }
}
