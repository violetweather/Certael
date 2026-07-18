import { lstatSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import type { NativeVerifier, SessionBinding, VerifiedAction } from "./index.js";

export interface NativeVerifiedEnvelope {
  actionId: string;
  sessionId: string;
  sequence: bigint;
  actionType: string;
  requestSchema: string;
  schemaVersion: number;
  protocolMajor: number;
  protocolMinor: number;
  payload: Uint8Array;
  signedDigest: Uint8Array;
}

export interface CertaelNativeAddon {
  certaelNodeAbiVersion(): number;
  evaluateWasmRule(
    module: Uint8Array,
    canonicalInput: Uint8Array,
    fuel?: bigint,
    deadlineMilliseconds?: number,
  ): Uint8Array;
  verifyActionEnvelope(
    input: Uint8Array,
    sessionId: string,
    bindingDigest: Uint8Array,
    ephemeralPublicKey: Uint8Array,
    protocolMinimum: number,
    protocolMaximum: number,
  ): NativeVerifiedEnvelope;
}

export interface VerifiedRequestContext {
  readonly actionId: string;
  readonly actionType: string;
  readonly requestSchema: string;
  readonly schemaVersion: number;
  readonly protocolMajor: number;
  readonly protocolMinor: number;
  readonly signedDigest: Uint8Array;
}

export interface NativeVerifierOptions<TRequest> {
  readonly nativePath?: string;
  readonly addon?: CertaelNativeAddon;
  readonly decodeRequest: (payload: Uint8Array, context: VerifiedRequestContext) => TRequest;
  readonly maximumPayloadBytes?: number;
}

export function loadCertaelNativeAddon(nativePath: string): CertaelNativeAddon {
  if (!isAbsolute(nativePath) || !nativePath.endsWith(".node"))
    throw new Error("Certael native addon path must be an absolute .node file path");
  const information = lstatSync(nativePath);
  if (!information.isFile() || information.isSymbolicLink()
      || information.size <= 0 || information.size > 64 * 1024 * 1024)
    throw new Error("Certael native addon must be a regular file no larger than 64 MiB");
  const loaded = createRequire(import.meta.url)(nativePath) as Partial<CertaelNativeAddon>;
  return validateCertaelNativeAddon(loaded);
}

export function loadPlatformNativeAddon(): CertaelNativeAddon {
  const packageName = platformPackageName(process.platform, process.arch);
  const require = createRequire(import.meta.url);
  let nativePath: string;
  try { nativePath = require.resolve(packageName); }
  catch { throw new Error(`Certael native package ${packageName} is not installed`); }
  return loadCertaelNativeAddon(nativePath);
}

export function createNativeVerifier<TRequest>(
  options: NativeVerifierOptions<TRequest>,
): NativeVerifier<TRequest> {
  if (options.addon !== undefined && options.nativePath !== undefined)
    throw new Error("Provide at most one Certael native addon or absolute native path");
  const addon = options.addon !== undefined ? validateCertaelNativeAddon(options.addon)
    : options.nativePath !== undefined ? loadCertaelNativeAddon(options.nativePath)
      : loadPlatformNativeAddon();
  const maximum = options.maximumPayloadBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024 * 1024)
    throw new Error("maximumPayloadBytes must be between 1 byte and 1 MiB");
  return {
    verify(envelope, binding): VerifiedAction<TRequest> {
      validateBinding(binding);
      if (envelope.byteLength === 0 || envelope.byteLength > maximum + 2048)
        throw new Error("Certael action envelope size is invalid");
      const native = addon.verifyActionEnvelope(envelope, binding.sessionId,
        binding.bindingDigest, binding.ephemeralPublicKey,
        binding.protocolMinimum, binding.protocolMaximum);
      validateNativeResult(native, binding, maximum);
      const context: VerifiedRequestContext = {
        actionId: native.actionId,
        actionType: native.actionType,
        requestSchema: native.requestSchema,
        schemaVersion: native.schemaVersion,
        protocolMajor: native.protocolMajor,
        protocolMinor: native.protocolMinor,
        signedDigest: Uint8Array.from(native.signedDigest),
      };
      return {
        actionId: native.actionId,
        sequence: native.sequence,
        actionType: native.actionType,
        request: options.decodeRequest(Uint8Array.from(native.payload), context),
        canonicalEnvelope: Uint8Array.from(envelope),
      };
    },
  };
}

function platformPackageName(platform: NodeJS.Platform, architecture: string): string {
  const value = `${platform}-${architecture}`;
  if (value === "win32-x64") return "@certael/server-win32-x64";
  if (value === "linux-x64") return "@certael/server-linux-x64";
  if (value === "darwin-arm64") return "@certael/server-darwin-arm64";
  if (value === "darwin-x64") return "@certael/server-darwin-x64";
  throw new Error(`Certael native verifier does not support ${value}`);
}

export function sessionBindingDigest(binding: Omit<SessionBinding, "bindingDigest">): Uint8Array {
  const hash = createHash("sha256");
  for (const value of [binding.sessionId, binding.tenantId, binding.gameId,
    binding.environmentId, binding.playerSubject, binding.matchId, binding.serverId,
    binding.buildId, binding.protectionProfileId, binding.signingKeyId]) {
    const bytes = Buffer.from(value, "utf8");
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.byteLength));
    hash.update(length).update(bytes);
  }
  const protocols = Buffer.alloc(8);
  protocols.writeUInt32BE(binding.protocolMinimum, 0);
  protocols.writeUInt32BE(binding.protocolMaximum, 4);
  hash.update(protocols);
  return hash.digest();
}

export function validateCertaelNativeAddon(
  value: Partial<CertaelNativeAddon>,
): CertaelNativeAddon {
  if (typeof value.certaelNodeAbiVersion !== "function"
      || value.certaelNodeAbiVersion() !== 2
      || typeof value.verifyActionEnvelope !== "function"
      || typeof value.evaluateWasmRule !== "function")
    throw new Error("Certael native addon ABI is unsupported");
  return value as CertaelNativeAddon;
}

function validateBinding(binding: SessionBinding): void {
  if (binding.bindingDigest.byteLength !== 32 || binding.ephemeralPublicKey.byteLength !== 32
      || !Number.isInteger(binding.protocolMinimum) || binding.protocolMinimum < 1
      || !Number.isInteger(binding.protocolMaximum)
      || binding.protocolMaximum < binding.protocolMinimum
      || binding.minimumSequence < 0n || binding.maximumSequence < binding.minimumSequence
      || binding.maximumSequence > 18_446_744_073_709_551_615n)
    throw new Error("Trusted Certael session binding is invalid");
}

function validateNativeResult(value: NativeVerifiedEnvelope, binding: SessionBinding,
  maximumPayloadBytes: number): void {
  if (value.sessionId !== binding.sessionId || value.actionId.length === 0
      || value.actionType.length === 0 || value.requestSchema.length === 0
      || typeof value.sequence !== "bigint" || value.sequence < 0n
      || !Number.isInteger(value.schemaVersion) || value.schemaVersion < 1
      || !Number.isInteger(value.protocolMajor)
      || value.protocolMajor < binding.protocolMinimum
      || value.protocolMajor > binding.protocolMaximum
      || value.payload.byteLength > maximumPayloadBytes
      || value.signedDigest.byteLength !== 32)
    throw new Error("Certael native verifier returned an invalid result");
}
