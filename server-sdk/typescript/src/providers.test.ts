import assert from "node:assert/strict";
import test from "node:test";
import {
  AgonesServerVerifier, EosIdentityVerifier, PlayFabServerVerifier,
  ProviderError, SteamIdentityVerifier,
} from "./providers.js";

const now = new Date("2030-01-01T00:00:00Z");

test("Steam verifier calls the authoritative endpoint and binds application", async () => {
  let url: URL | undefined; let redirect: RequestRedirect | undefined;
  const verifier = new SteamIdentityVerifier("publisher-key", (async (input, init) => {
    url = new URL(input.toString()); redirect = init?.redirect;
    return new Response('{"response":{"params":{"result":"OK","steamid":"7656119"}}}',
      { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch, () => now);
  const result = await verifier.verify({ provider: "steam", applicationId: "480",
    opaqueAssertion: Uint8Array.of(0xab, 0xcd), expiresAt: new Date(now.getTime() + 60_000) });
  assert.equal(result.subject, "7656119"); assert.equal(result.applicationId, "480");
  assert.equal(result.claimsDigest.byteLength, 32); assert.equal(redirect, "error");
  assert.equal(url?.hostname, "partner.steam-api.com");
  assert.equal(url?.searchParams.get("ticket"), "abcd");
});

test("EOS identity and PlayFab/Agones server adapters reject wrong authoritative context", async () => {
  const assertion = { provider: "eos", applicationId: "product",
    opaqueAssertion: Uint8Array.of(1), expiresAt: new Date(now.getTime() + 60_000) };
  const eos = new EosIdentityVerifier({ verifyIdToken: async () => ({ authenticated: true,
    productUserId: "puid", productId: "product", authoritativeResponse: Uint8Array.of(1) }) },
  () => now);
  assert.equal((await eos.verify(assertion)).subject, "puid");

  const playFab = new PlayFabServerVerifier({ verifyServer: async () => ({ authenticated: true,
    serverId: "server", titleId: "wrong", environmentId: "prod",
    authoritativeResponse: Uint8Array.of(2) }) }, () => now);
  await assert.rejects(playFab.verify({ provider: "playfab", gameId: "title",
    opaqueCredential: "secret" }), (error: unknown) => error instanceof ProviderError
      && error.publicReason === "PLAYFAB_SERVER_REJECTED");

  const agones = new AgonesServerVerifier({ verifyAllocation: async () => { throw new Error("secret"); } },
    () => now);
  await assert.rejects(agones.verify({ provider: "agones", gameId: "game",
    opaqueCredential: "token" }), (error: unknown) => error instanceof ProviderError
      && error.publicReason === "AGONES_UNAVAILABLE" && !error.message.includes("secret"));
});
