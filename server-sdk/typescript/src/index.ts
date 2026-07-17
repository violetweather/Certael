import { createHash, timingSafeEqual } from "node:crypto";

export type ActionOutcome<T> =
  | { outcome: "accepted"; response: T; revision: bigint; replayDigest: Uint8Array }
  | { outcome: "rejected"; publicReason: string }
  | { outcome: "indeterminate"; publicReason: "INDETERMINATE" };

export interface SessionBinding {
  tenantId: string; gameId: string; environmentId: string; sessionId: string;
  playerSubject: string; serverId: string; matchId: string; bindingDigest: Uint8Array;
}
export interface VerifiedAction<T> { actionId: string; sequence: bigint; actionType: string; request: T; canonicalEnvelope: Uint8Array; }
export interface SessionStore { find(sessionId: string, signal?: AbortSignal): Promise<SessionBinding | undefined>; }
export interface AdmissionStore { reserve(sessionId: string, actionId: string, sequence: bigint, signal?: AbortSignal): Promise<"reserved" | "duplicate" | "replay">; }
export interface AuthoritativeTransaction<TState, TResponse> {
  readonly state: TState; readonly revision: bigint;
  stageResult(actionId: string, result: ActionOutcome<TResponse>, signal?: AbortSignal): Promise<void>;
  stageEvent(eventId: string, eventType: string, schemaVersion: number, payload: Uint8Array, signal?: AbortSignal): Promise<void>;
  commit(signal?: AbortSignal): Promise<bigint>; rollback(): Promise<void>;
}
export interface AuthoritativeTransactionFactory<TState, TResponse> {
  begin(binding: SessionBinding, signal?: AbortSignal): Promise<AuthoritativeTransaction<TState, TResponse>>;
}
export interface NativeVerifier {
  verify(envelope: Uint8Array, binding: SessionBinding): Promise<VerifiedAction<unknown>> | VerifiedAction<unknown>;
}

export async function handleAction<TRequest, TResponse, TState>(options: {
  envelope: Uint8Array; sessionId: string; verifier: NativeVerifier; sessions: SessionStore;
  admission: AdmissionStore; transactions: AuthoritativeTransactionFactory<TState, TResponse>;
  execute: (action: VerifiedAction<TRequest>, state: TState, signal?: AbortSignal) => Promise<{
    response: TResponse; eventId: string; eventType: string; schemaVersion: number; payload: Uint8Array;
  }>;
  signal?: AbortSignal;
}): Promise<ActionOutcome<TResponse>> {
  const binding = await options.sessions.find(options.sessionId, options.signal);
  if (!binding) return { outcome: "rejected", publicReason: "SESSION_NOT_FOUND" };
  let action: VerifiedAction<TRequest>;
  try { action = await options.verifier.verify(options.envelope, binding) as VerifiedAction<TRequest>; }
  catch { return { outcome: "rejected", publicReason: "INVALID_ACTION_PROOF" }; }
  if (action.canonicalEnvelope.byteLength !== options.envelope.byteLength
      || !timingSafeEqual(action.canonicalEnvelope, options.envelope))
    return { outcome: "rejected", publicReason: "NONCANONICAL_ENVELOPE" };
  const admission = await options.admission.reserve(binding.sessionId, action.actionId, action.sequence, options.signal);
  if (admission !== "reserved") return { outcome: "rejected", publicReason: admission === "replay" ? "REPLAY" : "DUPLICATE_ACTION" };
  const transaction = await options.transactions.begin(binding, options.signal);
  try {
    const trusted = await options.execute(action, transaction.state, options.signal);
    const digest = replayDigest(action.canonicalEnvelope, trusted.payload);
    const expectedRevision = transaction.revision + 1n;
    const accepted: ActionOutcome<TResponse> = { outcome: "accepted", response: trusted.response, revision: expectedRevision, replayDigest: digest };
    await transaction.stageEvent(trusted.eventId, trusted.eventType, trusted.schemaVersion, trusted.payload, options.signal);
    await transaction.stageResult(action.actionId, accepted, options.signal);
    if (await transaction.commit(options.signal) !== expectedRevision) throw new Error("unexpected revision");
    return accepted;
  } catch {
    await transaction.rollback();
    return { outcome: "indeterminate", publicReason: "INDETERMINATE" };
  }
}

export function replayDigest(...canonicalParts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha256");
  for (const part of canonicalParts) { const length = Buffer.allocUnsafe(4); length.writeUInt32BE(part.byteLength); hash.update(length); hash.update(part); }
  return hash.digest();
}

export class CertaelApiClient {
  constructor(private readonly baseUrl: URL, private readonly fetcher: typeof fetch = fetch) {}
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetcher(new URL(path, this.baseUrl), init);
    if (!response.ok) throw new Error(`Certael API returned ${response.status}`);
    return await response.json() as T;
  }
  issueTicket(body: unknown, signal?: AbortSignal) { return this.request("/v1/tickets", { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" }, ...(signal ? { signal } : {}) }); }
  getEvidence(verdictId: string, signal?: AbortSignal) { return this.request(`/v1/evidence/${encodeURIComponent(verdictId)}`, signal ? { signal } : {}); }
  getCase(caseId: string, signal?: AbortSignal) { return this.request(`/v1/cases/${encodeURIComponent(caseId)}`, signal ? { signal } : {}); }
}
