import { createHash, timingSafeEqual } from "node:crypto";
import { sessionBindingDigest } from "./native.js";

export type ActionOutcome<T> =
  | { outcome: "accepted"; response: T; revision: bigint; replayDigest: Uint8Array }
  | { outcome: "rejected"; publicReason: string }
  | { outcome: "indeterminate"; publicReason: "INDETERMINATE" };

export interface SessionBinding {
  tenantId: string; gameId: string; environmentId: string; sessionId: string;
  playerSubject: string; serverId: string; matchId: string; buildId: string;
  protectionProfileId: string; signingKeyId: string; bindingDigest: Uint8Array;
  ephemeralPublicKey: Uint8Array; protocolMinimum: number; protocolMaximum: number;
  minimumSequence: bigint; maximumSequence: bigint; expiresAt: Date;
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
export interface NativeVerifier<TRequest = unknown> {
  verify(envelope: Uint8Array, binding: SessionBinding): Promise<VerifiedAction<TRequest>> | VerifiedAction<TRequest>;
}

export interface AuthoritativeEventPayload {
  readonly eventId: string;
  readonly eventType: string;
  readonly schemaVersion: number;
  readonly payload: Uint8Array;
}

export type Base64String = string;
export interface IssueTicketRequest {
  tenantId: string; gameId: string; environmentId: string; playerSubject: string;
  matchId: string; serverId: string; buildId: string; protectionProfile: string;
  ephemeralPublicKey: Base64String;
}
export interface SignedBootstrapTicketWire {
  claims: Base64String; signature: Base64String; keyId: string;
}
export interface RedeemSessionRequest {
  ticket: SignedBootstrapTicketWire; ephemeralPublicKey: Base64String;
  challenge: Base64String; possessionSignature: Base64String;
}
export interface ActiveSessionWire {
  sessionId: string; gameId: string; environmentId: string; playerSubject: string;
  matchId: string; serverId: string; buildId: string; expiresAt: string;
  initialSequence: number; bindingDigest: Base64String; protocolMinimum: number;
  protocolMaximum: number; protectionProfileId: string;
}
export interface SessionOperationRequest {
  tenantId: string; environmentId: string; authoritativeServerId: string;
}
export interface SessionRevocationRequest extends SessionOperationRequest { reason: string; }
export interface EvidenceSummaryWire {
  verdictId: string; tenantId: string; gameId: string; environmentId: string;
  sessionId: string; playerSubject: string; riskScore: number; confidence: number;
  recommendation: string; ruleIds: string[]; signalFamilies: string[];
  findingCount: number; createdAt: string;
}
export interface EvidenceSearchPageWire {
  items: EvidenceSummaryWire[]; nextCursor?: string | null; hasMore: boolean;
}
export interface EvidenceBundleWire {
  verdict: Record<string, unknown>; findings: Record<string, unknown>[];
  replayDigest: Base64String; signedPolicyId: string; signedPolicyVersion: string;
}
export interface CaseSummaryWire {
  caseId: string; tenantId: string; gameId: string; environmentId: string;
  playerSubject: string; title: string; summary: string; state: string;
  assignedTo?: string | null; category?: string | null; version: number;
  createdAt: string; updatedAt: string;
}
export interface CaseSearchPageWire {
  items: CaseSummaryWire[]; nextCursor?: string | null; hasMore: boolean;
}
export interface CaseDetailWire {
  case: CaseSummaryWire; evidence: Record<string, unknown>[];
  notes: Record<string, unknown>[]; assignments: Record<string, unknown>[];
  activity: Record<string, unknown>[]; dispositions: Record<string, unknown>[];
  actions: Record<string, unknown>[];
}
export interface CaseMutationRequest {
  tenantId: string; environmentId: string; expectedVersion: number;
}
export interface CaseAssignmentRequest extends CaseMutationRequest {
  assignedTo: string; reason: string;
}
export interface CaseNoteRequest extends CaseMutationRequest { body: string; }
export interface CaseTransitionRequest extends CaseMutationRequest {
  targetState: string; reason: string; disposition?: string | null;
}
export interface BoundedActionRequest extends CaseMutationRequest {
  actionType: string; targetId: string; reason: string; idempotencyKey: string;
}

export async function handleAction<TRequest, TResponse, TState>(options: {
  envelope: Uint8Array; sessionId: string; verifier: NativeVerifier<TRequest>; sessions: SessionStore;
  admission: AdmissionStore; transactions: AuthoritativeTransactionFactory<TState, TResponse>;
  execute: (action: VerifiedAction<TRequest>, state: TState, signal?: AbortSignal) => Promise<{
    response: TResponse; eventId: string; eventType: string; schemaVersion: number;
    payload: Uint8Array; additionalEvents?: readonly AuthoritativeEventPayload[];
  }>;
  clock?: () => Date;
  signal?: AbortSignal;
}): Promise<ActionOutcome<TResponse>> {
  const binding = await options.sessions.find(options.sessionId, options.signal);
  if (!binding) return { outcome: "rejected", publicReason: "SESSION_NOT_FOUND" };
  if (binding.sessionId !== options.sessionId)
    return { outcome: "rejected", publicReason: "INVALID_SESSION_BINDING" };
  const expiresAt = binding.expiresAt.getTime();
  if (!Number.isFinite(expiresAt) || expiresAt <= (options.clock?.() ?? new Date()).getTime())
    return { outcome: "rejected", publicReason: "SESSION_EXPIRED" };
  const expectedBinding = sessionBindingDigest(binding);
  if (binding.bindingDigest.byteLength !== expectedBinding.byteLength
      || !timingSafeEqual(binding.bindingDigest, expectedBinding))
    return { outcome: "rejected", publicReason: "INVALID_SESSION_BINDING" };
  let action: VerifiedAction<TRequest>;
  try { action = await options.verifier.verify(options.envelope, binding) as VerifiedAction<TRequest>; }
  catch { return { outcome: "rejected", publicReason: "INVALID_ACTION_PROOF" }; }
  if (typeof action.sequence !== "bigint" || action.sequence < 0n
      || typeof action.actionId !== "string" || !uuid(action.actionId)
      || typeof action.actionType !== "string" || action.actionType.length === 0
      || !(action.canonicalEnvelope instanceof Uint8Array))
    return { outcome: "rejected", publicReason: "INVALID_ACTION_PROOF" };
  if (action.sequence < binding.minimumSequence || action.sequence > binding.maximumSequence)
    return { outcome: "rejected", publicReason: "SEQUENCE_OUT_OF_RANGE" };
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
    if (trusted.additionalEvents !== undefined) {
      if (trusted.additionalEvents.length > 255) throw new Error("too many authoritative events");
      for (const event of trusted.additionalEvents)
        await transaction.stageEvent(event.eventId, event.eventType, event.schemaVersion,
          event.payload, options.signal);
    }
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
  private readonly baseUrl: URL;
  constructor(baseUrl: URL, private readonly fetcher: typeof fetch = fetch,
    private readonly defaultHeaders: HeadersInit | (() => HeadersInit) = {}) {
    this.baseUrl = new URL(baseUrl);
    if ((this.baseUrl.protocol !== "https:"
        && !(this.baseUrl.protocol === "http:"
          && ["localhost", "127.0.0.1", "::1"].includes(this.baseUrl.hostname)))
        || this.baseUrl.username !== "" || this.baseUrl.password !== ""
        || this.baseUrl.search !== "" || this.baseUrl.hash !== "")
      throw new Error("Certael API base URL must be HTTPS or loopback HTTP without credentials");
  }
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.send(path, init);
    const advertised = Number(response.headers.get("content-length") ?? "0");
    if (advertised > 1024 * 1024) throw new CertaelApiError(response.status,
      "Certael API response exceeded 1 MiB");
    const bytes = response.status === 204 ? new Uint8Array() : await boundedBody(response);
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { throw new CertaelApiError(response.status, "Certael API returned invalid UTF-8"); }
    if (!response.ok) throw new CertaelApiError(response.status,
      publicApiReason(text) ?? `Certael API returned ${response.status}`);
    if (text.length === 0) return undefined as T;
    try { return JSON.parse(text) as T; }
    catch { throw new CertaelApiError(response.status, "Certael API returned invalid JSON"); }
  }
  json<T>(path: string, method: "POST" | "PUT" | "DELETE", body: unknown,
    signal?: AbortSignal): Promise<T> {
    return this.request(path, { method, body: JSON.stringify(body),
      headers: { "content-type": "application/json", "accept": "application/json" },
      ...(signal === undefined ? {} : { signal }) });
  }
  async binary(path: string, method: "POST" | "PUT", body: Uint8Array,
    signal?: AbortSignal): Promise<Uint8Array> {
    if (!(body instanceof Uint8Array) || body.byteLength === 0
        || body.byteLength > 64 * 1024)
      throw new Error("Certael binary request size is invalid");
    const response = await this.send(path, { method, body: Buffer.from(body),
      headers: { "content-type": "application/x-protobuf",
        "accept": "application/x-protobuf" },
      ...(signal === undefined ? {} : { signal }) });
    const bytes = await boundedBody(response);
    if (!response.ok) throw new CertaelApiError(response.status,
      `Certael API returned ${response.status}`);
    return bytes;
  }
  issueTicket(body: IssueTicketRequest, signal?: AbortSignal) {
    return this.json<SignedBootstrapTicketWire>("/v1/sessions/tickets", "POST", body, signal);
  }
  redeemSession(body: RedeemSessionRequest, signal?: AbortSignal) {
    return this.json<ActiveSessionWire>("/v1/sessions/redeem", "POST", body, signal);
  }
  renewSession(sessionId: string, body: SessionOperationRequest, signal?: AbortSignal) {
    return this.json<{ sessionId: string; expiresAt: string }>(
      `/v1/sessions/${segment(sessionId)}/renew`, "POST", body, signal);
  }
  revokeSession(sessionId: string, body: SessionRevocationRequest, signal?: AbortSignal) {
    return this.json<void>(`/v1/sessions/${segment(sessionId)}/revoke`, "POST", body, signal);
  }
  createAgentSession(body: Uint8Array, signal?: AbortSignal) {
    return this.binary("/v1/agent/sessions", "POST", body, signal);
  }
  exchangeAgentChallenge(agentSessionId: string, body: Uint8Array,
    signal?: AbortSignal) {
    return this.binary(`/v1/agent/sessions/${segment(agentSessionId)}/challenge`,
      "POST", body, signal);
  }
  async submitAgentReport(agentSessionId: string, body: Uint8Array,
    signal?: AbortSignal) {
    await this.binary(`/v1/agent/sessions/${segment(agentSessionId)}/reports`,
      "POST", body, signal);
  }
  agentHealth(agentSessionId: string, body: Uint8Array, signal?: AbortSignal) {
    return this.binary(`/v1/agent/sessions/${segment(agentSessionId)}/health`,
      "POST", body, signal);
  }
  revokeAgentSession(agentSessionId: string, body: Uint8Array,
    signal?: AbortSignal) {
    return this.binary(`/v1/agent/sessions/${segment(agentSessionId)}/revoke`,
      "POST", body, signal);
  }
  registerAgentBuild<T = unknown>(body: unknown, signal?: AbortSignal) {
    return this.json<T>("/v1/admin/agent-builds", "POST", body, signal);
  }
  revokeAgentBuild<T = unknown>(body: unknown, signal?: AbortSignal) {
    return this.json<T>("/v1/admin/agent-builds/revoke", "POST", body, signal);
  }
  getEvidence(verdictId: string, query: URLSearchParams, signal?: AbortSignal) {
    return this.request<EvidenceBundleWire>(
      `/v1/evidence/${segment(verdictId)}?${query.toString()}`,
      signal === undefined ? {} : { signal });
  }
  getCase(caseId: string, query: URLSearchParams, signal?: AbortSignal) {
    return this.request<CaseDetailWire>(`/v1/cases/${segment(caseId)}?${query.toString()}`,
      signal === undefined ? {} : { signal });
  }
  searchEvidence(query: URLSearchParams, signal?: AbortSignal) {
    return this.request<EvidenceSearchPageWire>(`/v1/evidence/page?${query.toString()}`,
      signal === undefined ? {} : { signal });
  }
  searchCases(query: URLSearchParams, signal?: AbortSignal) {
    return this.request<CaseSearchPageWire>(`/v1/cases/page?${query.toString()}`,
      signal === undefined ? {} : { signal });
  }
  assignCase(caseId: string, body: CaseAssignmentRequest, signal?: AbortSignal) {
    return this.json<CaseSummaryWire>(`/v1/cases/${segment(caseId)}/assignment`,
      "POST", body, signal);
  }
  addCaseNote(caseId: string, body: CaseNoteRequest, signal?: AbortSignal) {
    return this.json<Record<string, unknown>>(`/v1/cases/${segment(caseId)}/notes`,
      "POST", body, signal);
  }
  transitionCase(caseId: string, body: CaseTransitionRequest, signal?: AbortSignal) {
    return this.json<CaseSummaryWire>(`/v1/cases/${segment(caseId)}/transition`,
      "POST", body, signal);
  }
  executeBoundedAction(caseId: string, body: BoundedActionRequest,
    signal?: AbortSignal) {
    return this.json<Record<string, unknown>>(`/v1/cases/${segment(caseId)}/actions`,
      "POST", body, signal);
  }

  private async send(path: string, init: RequestInit): Promise<Response> {
    if (!path.startsWith("/") || path.startsWith("//"))
      throw new Error("Certael API path must be root-relative");
    const url = new URL(path, this.baseUrl);
    if (url.origin !== this.baseUrl.origin)
      throw new Error("Certael API path changed origin");
    const defaults = typeof this.defaultHeaders === "function"
      ? this.defaultHeaders() : this.defaultHeaders;
    const headers = new Headers(defaults);
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    return this.fetcher(url, { ...init, headers, redirect: "error" });
  }
}

export class CertaelApiError extends Error {
  constructor(readonly status: number, message: string) { super(message); this.name = "CertaelApiError"; }
}

function segment(value: string): string {
  if (value.length === 0 || value.length > 256 || value.includes("/") || value.includes("\\"))
    throw new Error("Certael API identifier is invalid");
  return encodeURIComponent(value);
}

function uuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function publicApiReason(body: string): string | undefined {
  if (body.length === 0 || body.length > 64 * 1024) return undefined;
  try {
    const parsed = JSON.parse(body) as { reason?: unknown; title?: unknown };
    const value = typeof parsed.reason === "string" ? parsed.reason
      : typeof parsed.title === "string" ? parsed.title : undefined;
    return value !== undefined && value.length <= 256 ? value : undefined;
  } catch { return undefined; }
}

async function boundedBody(response: Response): Promise<Uint8Array> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (!Number.isFinite(advertised) || advertised < 0 || advertised > 1024 * 1024)
    throw new CertaelApiError(response.status, "Certael API response exceeded 1 MiB");
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > 1024 * 1024)
        throw new CertaelApiError(response.status, "Certael API response exceeded 1 MiB");
      chunks.push(next.value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

export * from "./native.js";
export * from "./stores.js";
export * from "./wasm.js";
export * from "./providers.js";
