import { createHash, timingSafeEqual, verify, type KeyLike } from "node:crypto";
import {
  loadCertaelNativeAddon,
  loadPlatformNativeAddon,
  validateCertaelNativeAddon,
  type CertaelNativeAddon,
} from "./native.js";

export type WasmRuleOutcome = "pass" | "reject" | "indeterminate";
export interface WasmRuleInputV1 {
  tenantId: string; gameId: string; environmentId: string;
  ruleId: string; ruleVersion: string;
  canonicalAction: Uint8Array; canonicalState: Uint8Array;
}
export interface WasmRuleDecisionV1 {
  outcome: WasmRuleOutcome; publicReason: string; boundedRisk: number;
  boundedEvidence: Readonly<Record<string, string>>;
}
export interface SignedWasmModule {
  ruleId: string; version: string; module: Uint8Array; digest: Uint8Array;
  keyId: string; signature: Uint8Array;
}
export interface WasmEvaluationLimits {
  fuel?: bigint; deadlineMilliseconds?: number;
}

const maximumInput = 1024 * 1024;
const maximumOutput = 64 * 1024;
const maximumModule = 4 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class SignedWasmRuleRegistry {
  readonly #modules = new Map<string, SignedWasmModule>();
  readonly #keys: ReadonlyMap<string, KeyLike>;
  readonly #addon: CertaelNativeAddon;

  constructor(keys: ReadonlyMap<string, KeyLike>, options: {
    addon?: CertaelNativeAddon; nativePath?: string;
  } = {}) {
    if (options.addon !== undefined && options.nativePath !== undefined)
      throw new Error("Provide at most one Certael native addon or absolute path");
    this.#keys = keys;
    this.#addon = options.addon !== undefined ? validateCertaelNativeAddon(options.addon)
      : (options.nativePath === undefined
      ? loadPlatformNativeAddon() : loadCertaelNativeAddon(options.nativePath));
  }

  register(value: SignedWasmModule): void {
    if (!identifier(value.ruleId) || !identifier(value.version) || !identifier(value.keyId)
        || value.module.byteLength < 8 || value.module.byteLength > maximumModule
        || value.digest.byteLength !== 32 || value.signature.byteLength !== 64)
      throw new Error("Signed WASM module fields are invalid");
    const digest = createHash("sha256").update(value.module).digest();
    if (!timingSafeEqual(digest, value.digest))
      throw new Error("Signed WASM module digest is invalid");
    const key = this.#keys.get(value.keyId);
    if (key === undefined || !verify(null, signaturePayload(value.ruleId, value.version,
        value.digest), key, value.signature))
      throw new Error("Signed WASM module signature is invalid");
    const id = digest.toString("hex");
    const existing = this.#modules.get(id);
    if (existing !== undefined && (existing.ruleId !== value.ruleId
        || existing.version !== value.version
        || !timingSafeEqual(existing.module, value.module)))
      throw new Error("WASM module digest is registered differently");
    this.#modules.set(id, { ...value, module: Uint8Array.from(value.module),
      digest: Uint8Array.from(value.digest), signature: Uint8Array.from(value.signature) });
  }

  evaluate(digest: Uint8Array, input: WasmRuleInputV1,
    limits: WasmEvaluationLimits = {}): WasmRuleDecisionV1 {
    if (digest.byteLength !== 32) return indeterminate("WASM_MODULE_UNAVAILABLE");
    const module = this.#modules.get(Buffer.from(digest).toString("hex"));
    if (module === undefined) return indeterminate("WASM_MODULE_UNAVAILABLE");
    if (module.ruleId !== input.ruleId || module.version !== input.ruleVersion)
      return indeterminate("WASM_PROFILE_BINDING_MISMATCH");
    try {
      const encoded = encodeWasmRuleInput(input);
      const output = this.#addon.evaluateWasmRule(module.module, encoded,
        limits.fuel, limits.deadlineMilliseconds);
      return decodeWasmRuleDecision(output);
    } catch { return indeterminate("WASM_INDETERMINATE"); }
  }
}

export function encodeWasmRuleInput(value: WasmRuleInputV1): Uint8Array {
  if (!identifier(value.tenantId) || !identifier(value.gameId)
      || !identifier(value.environmentId) || !identifier(value.ruleId)
      || !identifier(value.ruleVersion) || value.canonicalAction.byteLength === 0
      || value.canonicalAction.byteLength + value.canonicalState.byteLength > maximumInput)
    throw new Error("WASM input fields are invalid");
  const result = concat(fieldUnsigned(1, 1), fieldBytes(2, encoder.encode(value.tenantId)),
    fieldBytes(3, encoder.encode(value.gameId)),
    fieldBytes(4, encoder.encode(value.environmentId)),
    fieldBytes(5, encoder.encode(value.ruleId)),
    fieldBytes(6, encoder.encode(value.ruleVersion)),
    fieldBytes(7, value.canonicalAction), fieldBytes(8, value.canonicalState));
  if (result.byteLength > maximumInput) throw new Error("WASM input exceeds 1 MiB");
  return result;
}

export function decodeWasmRuleDecision(encoded: Uint8Array): WasmRuleDecisionV1 {
  if (encoded.byteLength === 0 || encoded.byteLength > maximumOutput)
    throw new Error("WASM decision size is invalid");
  const reader = new ProtoReader(encoded);
  if (reader.unsigned(1) !== 1n) throw new Error("WASM decision schema is unsupported");
  const outcomeValue = reader.unsigned(2);
  const outcome = outcomeValue === 1n ? "pass" : outcomeValue === 2n ? "reject"
    : outcomeValue === 3n ? "indeterminate" : undefined;
  const publicReason = reader.string(3);
  const risk = Number(reader.unsigned(4));
  const evidence: Record<string, string> = Object.create(null) as Record<string, string>;
  while (!reader.end) {
    const entry = new ProtoReader(reader.bytes(5, maximumOutput, true));
    const key = entry.string(1); const value = entry.string(2); entry.requireEnd();
    if (Object.hasOwn(evidence, key)) throw new Error("Duplicate WASM evidence key");
    evidence[key] = value;
  }
  if (outcome === undefined || !identifier(publicReason, 64)
      || !Number.isSafeInteger(risk) || risk < 0 || risk > 100
      || Object.keys(evidence).length > 64
      || Object.entries(evidence).some(([key, value]) => !identifier(key, 64)
        || value.length > 4096 || [...value].some(character => /\p{Cc}/u.test(character))))
    throw new Error("WASM decision fields are invalid");
  const decision = { outcome, publicReason, boundedRisk: risk,
    boundedEvidence: evidence } satisfies WasmRuleDecisionV1;
  if (!timingSafeEqual(encodeWasmRuleDecision(decision), encoded))
    throw new Error("WASM decision is not canonical");
  return decision;
}

export function encodeWasmRuleDecision(value: WasmRuleDecisionV1): Uint8Array {
  const outcome = value.outcome === "pass" ? 1 : value.outcome === "reject" ? 2
    : value.outcome === "indeterminate" ? 3 : 0;
  const entries = Object.entries(value.boundedEvidence).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0);
  if (outcome === 0 || !identifier(value.publicReason, 64)
      || !Number.isSafeInteger(value.boundedRisk) || value.boundedRisk < 0
      || value.boundedRisk > 100 || entries.length > 64
      || entries.some(([key, entry]) => !identifier(key, 64) || entry.length > 4096
        || [...entry].some(character => /\p{Cc}/u.test(character))))
    throw new Error("WASM decision fields are invalid");
  const fields = [fieldUnsigned(1, 1), fieldUnsigned(2, outcome),
    fieldBytes(3, encoder.encode(value.publicReason)), fieldUnsigned(4, value.boundedRisk)];
  for (const [key, entry] of entries)
    fields.push(fieldBytes(5, concat(fieldBytes(1, encoder.encode(key)),
      fieldBytes(2, encoder.encode(entry)))));
  const result = concat(...fields);
  if (result.byteLength > maximumOutput) throw new Error("WASM decision exceeds 64 KiB");
  return result;
}

export function wasmSignaturePayload(ruleId: string, version: string,
  digest: Uint8Array): Uint8Array {
  if (!identifier(ruleId) || !identifier(version) || digest.byteLength !== 32)
    throw new Error("WASM signature binding is invalid");
  const domain = encoder.encode("certael.wasm.module.v1\0");
  return concat(domain, framed(ruleId), framed(version), digest);
}

function signaturePayload(ruleId: string, version: string, digest: Uint8Array): Uint8Array {
  return wasmSignaturePayload(ruleId, version, digest);
}
function indeterminate(publicReason: string): WasmRuleDecisionV1 {
  return { outcome: "indeterminate", publicReason, boundedRisk: 0,
    boundedEvidence: Object.freeze({}) };
}
function identifier(value: string, maximum = 128): boolean {
  return value.length > 0 && value.length <= maximum && /^[A-Za-z0-9._:-]+$/.test(value);
}
function framed(value: string): Uint8Array {
  const bytes = encoder.encode(value); const result = new Uint8Array(4 + bytes.byteLength);
  new DataView(result.buffer).setUint32(0, bytes.byteLength, false); result.set(bytes, 4); return result;
}
function fieldUnsigned(field: number, value: number): Uint8Array {
  return concat(varint(BigInt(field << 3)), varint(BigInt(value)));
}
function fieldBytes(field: number, value: Uint8Array): Uint8Array {
  return concat(varint(BigInt((field << 3) | 2)), varint(BigInt(value.byteLength)), value);
}
function varint(value: bigint): Uint8Array {
  const bytes: number[] = [];
  do { let current = Number(value & 0x7fn); value >>= 7n;
    if (value !== 0n) current |= 0x80; bytes.push(current); } while (value !== 0n);
  return Uint8Array.from(bytes);
}
function concat(...values: readonly Uint8Array[]): Uint8Array {
  const total = values.reduce((sum, value) => sum + value.byteLength, 0);
  const result = new Uint8Array(total); let offset = 0;
  for (const value of values) { result.set(value, offset); offset += value.byteLength; }
  return result;
}

class ProtoReader {
  #offset = 0; #lastField = 0;
  constructor(readonly input: Uint8Array) {}
  get end(): boolean { return this.#offset === this.input.byteLength; }
  unsigned(field: number): bigint { this.#key(field, 0, false); return this.#varint(); }
  string(field: number): string { return decoder.decode(this.bytes(field, 4096)); }
  bytes(field: number, maximum: number, repeated = false): Uint8Array {
    this.#key(field, 2, repeated); const raw = this.#varint();
    if (raw > BigInt(maximum)) throw new Error("WASM protobuf length is invalid");
    const length = Number(raw); const end = this.#offset + length;
    if (end > this.input.byteLength) throw new Error("WASM protobuf is truncated");
    const result = this.input.slice(this.#offset, end); this.#offset = end; return result;
  }
  requireEnd(): void { if (!this.end) throw new Error("WASM protobuf has trailing fields"); }
  #key(expected: number, wire: number, repeated: boolean): void {
    const key = this.#varint(); const field = Number(key >> 3n);
    if (field !== expected || field < this.#lastField
        || (field === this.#lastField && !repeated) || Number(key & 7n) !== wire)
      throw new Error("WASM protobuf field order is invalid");
    this.#lastField = field;
  }
  #varint(): bigint {
    const start = this.#offset; let value = 0n;
    for (let shift = 0n; shift <= 63n; shift += 7n) {
      if (this.#offset >= this.input.byteLength) throw new Error("WASM protobuf is truncated");
      const current = this.input[this.#offset++]!;
      if (shift === 63n && current > 1) throw new Error("WASM protobuf varint overflows");
      value |= BigInt(current & 0x7f) << shift;
      if ((current & 0x80) === 0) {
        const canonical = varint(value);
        if (!timingSafeEqual(canonical, this.input.slice(start, this.#offset)))
          throw new Error("WASM protobuf varint is not minimal");
        return value;
      }
    }
    throw new Error("WASM protobuf varint overflows");
  }
}
