import { createHash } from "node:crypto";

export interface ExternalIdentityAssertion {
  provider: string; applicationId: string; opaqueAssertion: Uint8Array; expiresAt: Date;
}
export interface VerifiedPlayerIdentity {
  provider: string; subject: string; applicationId: string;
  claimsDigest: Uint8Array; verifiedAt: Date;
}
export interface AuthoritativeServerCredential {
  provider: string; gameId: string; opaqueCredential: string;
}
export interface VerifiedServerIdentity {
  provider: string; serverId: string; gameId: string; environmentId: string;
  allocationId?: string; claimsDigest: Uint8Array; verifiedAt: Date;
}
export interface PlayerIdentityVerifier {
  readonly provider: string;
  verify(assertion: ExternalIdentityAssertion, signal?: AbortSignal):
    Promise<VerifiedPlayerIdentity>;
}
export interface AuthoritativeServerVerifier {
  readonly provider: string;
  verify(credential: AuthoritativeServerCredential, signal?: AbortSignal):
    Promise<VerifiedServerIdentity>;
}

export class ProviderError extends Error {
  constructor(readonly publicReason: string, message: string) { super(message); }
}

export interface EosConnectResult {
  authenticated: boolean; productUserId: string; productId: string;
  authoritativeResponse: Uint8Array;
}
export interface EosConnectClient {
  verifyIdToken(productId: string, token: Uint8Array, signal?: AbortSignal):
    Promise<EosConnectResult>;
}
export interface PlayFabServerResult {
  authenticated: boolean; serverId: string; titleId: string; environmentId: string;
  authoritativeResponse: Uint8Array;
}
export interface PlayFabServerClient {
  verifyServer(titleId: string, credential: string, signal?: AbortSignal):
    Promise<PlayFabServerResult>;
}
export interface AgonesAllocationResult {
  allocated: boolean; gameServerName: string; gameId: string; environmentId: string;
  allocationId: string; authoritativeResponse: Uint8Array;
}
export interface AgonesClient {
  verifyAllocation(gameId: string, token: string, signal?: AbortSignal):
    Promise<AgonesAllocationResult>;
}

export class SteamIdentityVerifier implements PlayerIdentityVerifier {
  readonly provider = "steam";
  constructor(private readonly publisherWebApiKey: string,
    private readonly fetcher: typeof fetch = fetch,
    private readonly clock: () => Date = () => new Date()) {
    if (!secret(publisherWebApiKey)) throw new ProviderError("STEAM_CONFIGURATION_INVALID",
      "Steam publisher Web API key is invalid");
  }
  async verify(assertion: ExternalIdentityAssertion,
    signal?: AbortSignal): Promise<VerifiedPlayerIdentity> {
    validateAssertion(assertion, this.provider, this.clock());
    const endpoint = new URL("https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/");
    endpoint.searchParams.set("key", this.publisherWebApiKey);
    endpoint.searchParams.set("appid", assertion.applicationId);
    endpoint.searchParams.set("ticket", Buffer.from(assertion.opaqueAssertion).toString("hex"));
    let response: Response;
    const init: RequestInit = signal === undefined
      ? { method: "GET", redirect: "error" }
      : { method: "GET", redirect: "error", signal };
    try { response = await this.fetcher(endpoint, init); }
    catch (error) {
      if (signal?.aborted === true) throw error;
      throw new ProviderError("STEAM_UNAVAILABLE", "Steam identity verification is unavailable");
    }
    if (!response.ok) throw new ProviderError("STEAM_IDENTITY_REJECTED",
      "Steam rejected the identity assertion");
    const raw = await boundedBody(response, 64 * 1024, "STEAM_RESPONSE_INVALID");
    let parsed: unknown;
    try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
    catch { throw new ProviderError("STEAM_RESPONSE_INVALID", "Steam response is invalid"); }
    const parameters = record(record(parsed)?.response)?.params;
    const values = record(parameters);
    if (values?.result !== "OK" || !identifier(values.steamid)
        || String(values.vacbanned ?? "false").length > 16
        || String(values.publisherbanned ?? "false").length > 16)
      throw new ProviderError("STEAM_IDENTITY_REJECTED", "Steam rejected the identity assertion");
    return verified(this.provider, values.steamid, assertion.applicationId, raw, this.clock());
  }
}

export class EosIdentityVerifier implements PlayerIdentityVerifier {
  readonly provider = "eos";
  constructor(private readonly client: EosConnectClient,
    private readonly clock: () => Date = () => new Date()) {}
  async verify(assertion: ExternalIdentityAssertion,
    signal?: AbortSignal): Promise<VerifiedPlayerIdentity> {
    validateAssertion(assertion, this.provider, this.clock());
    let result: EosConnectResult;
    try { result = await this.client.verifyIdToken(assertion.applicationId,
      assertion.opaqueAssertion, signal); }
    catch (error) {
      if (signal?.aborted === true) throw error;
      throw new ProviderError("EOS_UNAVAILABLE", "EOS identity verification is unavailable");
    }
    validateResponse(result.authoritativeResponse);
    if (!result.authenticated || result.productId !== assertion.applicationId
        || !identifier(result.productUserId))
      throw new ProviderError("EOS_IDENTITY_REJECTED", "EOS rejected the identity assertion");
    return verified(this.provider, result.productUserId, result.productId,
      result.authoritativeResponse, this.clock());
  }
}

export class PlayFabServerVerifier implements AuthoritativeServerVerifier {
  readonly provider = "playfab";
  constructor(private readonly client: PlayFabServerClient,
    private readonly clock: () => Date = () => new Date()) {}
  async verify(credential: AuthoritativeServerCredential,
    signal?: AbortSignal): Promise<VerifiedServerIdentity> {
    validateCredential(credential, this.provider);
    let result: PlayFabServerResult;
    try { result = await this.client.verifyServer(credential.gameId,
      credential.opaqueCredential, signal); }
    catch (error) {
      if (signal?.aborted === true) throw error;
      throw new ProviderError("PLAYFAB_UNAVAILABLE", "PlayFab verification is unavailable");
    }
    validateResponse(result.authoritativeResponse);
    if (!result.authenticated || result.titleId !== credential.gameId
        || !identifier(result.serverId) || !identifier(result.environmentId))
      throw new ProviderError("PLAYFAB_SERVER_REJECTED", "PlayFab rejected the server credential");
    return server(this.provider, result.serverId, result.titleId, result.environmentId,
      undefined, result.authoritativeResponse, this.clock());
  }
}

export class AgonesServerVerifier implements AuthoritativeServerVerifier {
  readonly provider = "agones";
  constructor(private readonly client: AgonesClient,
    private readonly clock: () => Date = () => new Date()) {}
  async verify(credential: AuthoritativeServerCredential,
    signal?: AbortSignal): Promise<VerifiedServerIdentity> {
    validateCredential(credential, this.provider);
    let result: AgonesAllocationResult;
    try { result = await this.client.verifyAllocation(credential.gameId,
      credential.opaqueCredential, signal); }
    catch (error) {
      if (signal?.aborted === true) throw error;
      throw new ProviderError("AGONES_UNAVAILABLE", "Agones verification is unavailable");
    }
    validateResponse(result.authoritativeResponse);
    if (!result.allocated || result.gameId !== credential.gameId
        || !identifier(result.gameServerName) || !identifier(result.environmentId)
        || !identifier(result.allocationId))
      throw new ProviderError("AGONES_SERVER_REJECTED", "Agones rejected the allocation");
    return server(this.provider, result.gameServerName, result.gameId, result.environmentId,
      result.allocationId, result.authoritativeResponse, this.clock());
  }
}

function validateAssertion(value: ExternalIdentityAssertion, provider: string, now: Date): void {
  const expiresAt = value.expiresAt.getTime(); const current = now.getTime();
  if (value.provider !== provider || !identifier(value.applicationId)
      || !(value.opaqueAssertion instanceof Uint8Array)
      || value.opaqueAssertion.byteLength < 1 || value.opaqueAssertion.byteLength > 1024 * 1024
      || !Number.isFinite(expiresAt) || expiresAt <= current || expiresAt - current > 10 * 60_000)
    throw new ProviderError("IDENTITY_ASSERTION_INVALID", "External identity assertion is invalid");
}
function validateCredential(value: AuthoritativeServerCredential, provider: string): void {
  if (value.provider !== provider || !identifier(value.gameId) || !secret(value.opaqueCredential))
    throw new ProviderError("SERVER_CREDENTIAL_INVALID", "Server credential is invalid");
}
function validateResponse(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > 1024 * 1024)
    throw new ProviderError("PROVIDER_RESPONSE_INVALID", "Provider response is invalid");
}
function verified(provider: string, subject: string, applicationId: string,
  authoritative: Uint8Array, now: Date): VerifiedPlayerIdentity {
  validateResponse(authoritative);
  if (!identifier(subject) || !identifier(applicationId))
    throw new ProviderError("PROVIDER_RESPONSE_INVALID", "Provider response is invalid");
  return { provider, subject, applicationId,
    claimsDigest: createHash("sha256").update(authoritative).digest(), verifiedAt: now };
}
function server(provider: string, serverId: string, gameId: string, environmentId: string,
  allocationId: string | undefined, authoritative: Uint8Array, now: Date): VerifiedServerIdentity {
  const base = { provider, serverId, gameId, environmentId,
    claimsDigest: createHash("sha256").update(authoritative).digest(), verifiedAt: now };
  return allocationId === undefined ? base : { ...base, allocationId };
}
function identifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128
    && /^[A-Za-z0-9._:-]+$/.test(value);
}
function secret(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4096
    && ![...value].some(character => /\p{Cc}/u.test(character));
}
function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}
async function boundedBody(response: Response, maximum: number,
  reason: string): Promise<Uint8Array> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (!Number.isFinite(advertised) || advertised < 0 || advertised > maximum)
    throw new ProviderError(reason, "Provider response exceeded its size limit");
  if (response.body === null) throw new ProviderError(reason, "Provider response is empty");
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let total = 0;
  try {
    while (true) { const next = await reader.read(); if (next.done) break;
      total += next.value.byteLength;
      if (total > maximum) throw new ProviderError(reason, "Provider response exceeded its size limit");
      chunks.push(next.value); }
  } finally { reader.releaseLock(); }
  const output = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  if (output.byteLength === 0) throw new ProviderError(reason, "Provider response is empty");
  return output;
}
