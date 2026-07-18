import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import { MemoryArtifactStore } from "../src/lib/artifact-store.js";
import { loadConfig, type AppConfig } from "../src/lib/config.js";
import { parseRegistry } from "../src/lib/registry.js";
import { signServiceRequest } from "../src/lib/request-auth.js";
import { TOKEN_TYPES } from "../src/lib/token-types.js";
import { sign } from "../src/lib/tokens.js";
import { createApp } from "../src/server.js";

const clientId = "test-client";
const clientSecret = "test-client-secret-with-sufficient-entropy";
const attackerClientId = "other-tenant";
const attackerClientSecret = "other-tenant-secret-with-sufficient-entropy";
const brokerSecret = "test-broker-secret-with-sufficient-entropy";
const originalFetch = globalThis.fetch;
let providerExchangeCount = 0;
let squareRefreshCount = 0;
let stripeRevokeCount = 0;

const config: AppConfig = {
  port: 0,
  databaseUrl: "postgres://unused",
  brokerPublicUrl: "http://localhost",
  brokerSigningSecret: brokerSecret,
  stripeConnectClientId: "ca_test",
  stripePlatformSecretKey: "sk_test_placeholder",
  squareAppId: "square-test",
  squareAppSecret: "square-secret",
  squareOAuthEnv: "sandbox",
  squareApiVersion: "2026-05-20",
  squareOAuthScopes: ["PAYMENTS_READ", "PAYMENTS_WRITE"],
  providerTimeoutMs: 1_000,
};

const store = new MemoryArtifactStore();
const app = createApp(config, {
  [clientId]: { secret: clientSecret, returnOrigin: "https://client.example.com" },
  [attackerClientId]: {
    secret: attackerClientSecret,
    returnOrigin: "https://other-client.example.com",
  },
}, store);
const server = createServer(app);
let baseUrl = "";

before(async () => {
  await store.initialize();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
  globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input : input.url);
    if (url.hostname === "connect.stripe.com" && url.pathname === "/oauth/token") {
      providerExchangeCount += 1;
      return new Response(JSON.stringify({
        access_token: "access_token_must_never_enter_browser_url",
        refresh_token: "refresh_token_must_never_enter_browser_url",
        stripe_user_id: "acct_test",
        livemode: false,
        scope: "read_write",
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (url.hostname === "connect.stripe.com" && url.pathname === "/oauth/deauthorize") {
      stripeRevokeCount += 1;
      return new Response(JSON.stringify({ stripe_user_id: "acct_test" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.hostname === "connect.squareupsandbox.com" && url.pathname === "/oauth2/token") {
      const rawBody = typeof init?.body === "string" ? init.body : "{}";
      const body = JSON.parse(rawBody) as { grant_type?: string };
      if (body.grant_type === "refresh_token") squareRefreshCount += 1;
      return new Response(JSON.stringify({
        access_token: body.grant_type === "refresh_token" ? "square-access-refreshed" : "square-access-initial",
        refresh_token: "square-provider-refresh-secret",
        merchant_id: "merchant-1",
        expires_at: "2026-08-18T00:00:00Z",
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return originalFetch(input, init);
  };
});

test("Square refresh signatures are site/path/time bound and exact replay stops before the provider", async () => {
  const now = Math.floor(Date.now() / 1000);
  const nonce = "square-browser-session";
  const clientState = sign({
    typ: TOKEN_TYPES.clientState,
    v: 1,
    siteId: "site-square",
    provider: "square",
    returnUrl: "https://client.example.com/api/payments/connect/square/callback",
    nonce,
    iat: now,
    exp: now + 600,
  }, clientSecret);
  const start = await originalFetch(
    `${baseUrl}/connect/square/start?client_id=${clientId}&state=${encodeURIComponent(clientState)}`,
    { redirect: "manual" },
  );
  const authorizeUrl = new URL(assertString(start.headers.get("location")));
  const callback = await originalFetch(
    `${baseUrl}/connect/square/callback?code=square-code&state=${encodeURIComponent(assertString(authorizeUrl.searchParams.get("state")))}`,
    { redirect: "manual", headers: { cookie: cookieHeader(start) } },
  );
  const opaqueCode = assertString(new URL(assertString(callback.headers.get("location"))).searchParams.get("code"));

  const redeemBody = serviceEnvelope("site-square", "square", { code: opaqueCode, nonce });
  const redeemRaw = JSON.stringify(redeemBody);
  const redeem = await originalFetch(`${baseUrl}/connect/handoff/redeem`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-admitone-signature": signServiceRequest("POST", "/connect/handoff/redeem", redeemRaw, redeemBody, clientSecret),
    },
    body: redeemRaw,
  });
  assert.equal(redeem.status, 200);
  const handoff = await redeem.json() as { handoff: { data: { refreshToken: string } } };
  const refreshHandle = handoff.handoff.data.refreshToken;
  assert.equal(refreshHandle.includes("square-provider-refresh-secret"), false);

  const refreshBody = serviceEnvelope("site-square", "square", { refreshToken: refreshHandle });
  const refreshRaw = JSON.stringify(refreshBody);
  const refreshSignature = signServiceRequest("POST", "/connect/square/refresh", refreshRaw, refreshBody, clientSecret);
  const refresh = await originalFetch(`${baseUrl}/connect/square/refresh`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admitone-signature": refreshSignature },
    body: refreshRaw,
  });
  assert.equal(refresh.status, 200);
  assert.equal(squareRefreshCount, 1);

  const replay = await originalFetch(`${baseUrl}/connect/square/refresh`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admitone-signature": refreshSignature },
    body: refreshRaw,
  });
  assert.equal(replay.status, 409);
  assert.equal(squareRefreshCount, 1);

  const substitutedPathBody = serviceEnvelope("site-square", "square", { refreshToken: refreshHandle });
  const substitutedRaw = JSON.stringify(substitutedPathBody);
  const wrongPathSignature = signServiceRequest(
    "POST",
    "/connect/handoff/redeem",
    substitutedRaw,
    substitutedPathBody,
    clientSecret,
  );
  const substituted = await originalFetch(`${baseUrl}/connect/square/refresh`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admitone-signature": wrongPathSignature },
    body: substitutedRaw,
  });
  assert.equal(substituted.status, 401);
  assert.equal(squareRefreshCount, 1);
});

after(async () => {
  globalThis.fetch = originalFetch;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await store.close();
});

test("OAuth state and opaque handoff codes are one-time and credentials stay off the browser URL", async () => {
  const now = Math.floor(Date.now() / 1000);
  const nonce = "browser-session-nonce";
  const clientState = sign({
    typ: TOKEN_TYPES.clientState,
    v: 1,
    siteId: "site-1",
    provider: "stripe",
    returnUrl: "https://client.example.com/api/payments/connect/stripe/callback",
    nonce,
    iat: now,
    exp: now + 600,
  }, clientSecret);

  const start = await originalFetch(
    `${baseUrl}/connect/stripe/start?client_id=${clientId}&state=${encodeURIComponent(clientState)}`,
    { redirect: "manual" },
  );
  assert.equal(start.status, 302);
  assert.equal(start.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(start.headers.get("referrer-policy"), "no-referrer");
  const authorizeUrl = new URL(assertString(start.headers.get("location")));
  const brokerState = assertString(authorizeUrl.searchParams.get("state"));
  const brokerCookie = cookieHeader(start);

  const callbackUrl = `${baseUrl}/connect/stripe/callback?code=provider-code&state=${encodeURIComponent(brokerState)}`;
  const exchangeCountBeforeInjection = providerExchangeCount;
  const injectedCallback = await originalFetch(callbackUrl, { redirect: "manual" });
  assert.equal(injectedCallback.status, 401);
  assert.equal(providerExchangeCount, exchangeCountBeforeInjection);

  const callback = await originalFetch(callbackUrl, {
    redirect: "manual",
    headers: { cookie: brokerCookie },
  });
  assert.equal(callback.status, 302);
  const browserRedirect = assertString(callback.headers.get("location"));
  const parsedRedirect = new URL(browserRedirect);
  const opaqueCode = assertString(parsedRedirect.searchParams.get("code"));
  assert.match(opaqueCode, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(parsedRedirect.searchParams.has("handoff"), false);
  assert.equal(browserRedirect.includes("access_token"), false);
  assert.equal(browserRedirect.includes("refresh_token"), false);

  const replayedCallback = await originalFetch(callbackUrl, {
    redirect: "manual",
    headers: { cookie: brokerCookie },
  });
  assert.equal(replayedCallback.status, 409);
  assert.equal(providerExchangeCount, 1);

  const requestBody = serviceBody({
    code: opaqueCode,
    nonce,
    provider: "stripe",
  });
  const rawBody = JSON.stringify(requestBody);
  const signature = signServiceRequest(
    "POST",
    "/connect/handoff/redeem",
    rawBody,
    requestBody,
    clientSecret,
  );
  const redeem = await originalFetch(`${baseUrl}/connect/handoff/redeem`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admitone-signature": signature },
    body: rawBody,
  });
  assert.equal(redeem.status, 200);
  const redeemed = await redeem.json() as { handoff: { data: { accessToken: string; refreshToken: string } } };
  assert.equal(redeemed.handoff.data.accessToken, "access_token_must_never_enter_browser_url");
  assert.equal(redeemed.handoff.data.refreshToken, "refresh_token_must_never_enter_browser_url");

  const exactReplay = await originalFetch(`${baseUrl}/connect/handoff/redeem`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admitone-signature": signature },
    body: rawBody,
  });
  assert.equal(exactReplay.status, 409);

  const secondRequest = serviceBody({ code: opaqueCode, nonce, provider: "stripe" });
  const secondRawBody = JSON.stringify(secondRequest);
  const consumedReplay = await originalFetch(`${baseUrl}/connect/handoff/redeem`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-admitone-signature": signServiceRequest(
        "POST",
        "/connect/handoff/redeem",
        secondRawBody,
        secondRequest,
        clientSecret,
      ),
    },
    body: secondRawBody,
  });
  assert.equal(consumedReplay.status, 409);

  const attackerRevokeBody = serviceEnvelope(
    "attacker-site",
    "stripe",
    { externalAccountId: "acct_test" },
    attackerClientId,
  );
  const attackerRevokeRaw = JSON.stringify(attackerRevokeBody);
  const attackerRevoke = await originalFetch(`${baseUrl}/connect/stripe/revoke`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-admitone-signature": signServiceRequest(
        "POST",
        "/connect/stripe/revoke",
        attackerRevokeRaw,
        attackerRevokeBody,
        attackerClientSecret,
      ),
    },
    body: attackerRevokeRaw,
  });
  assert.equal(attackerRevoke.status, 403);
  assert.equal(stripeRevokeCount, 0);

  const ownerRevokeBody = serviceEnvelope("site-1", "stripe", { externalAccountId: "acct_test" });
  const ownerRevokeRaw = JSON.stringify(ownerRevokeBody);
  const ownerRevoke = await originalFetch(`${baseUrl}/connect/stripe/revoke`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-admitone-signature": signServiceRequest(
        "POST",
        "/connect/stripe/revoke",
        ownerRevokeRaw,
        ownerRevokeBody,
        clientSecret,
      ),
    },
    body: ownerRevokeRaw,
  });
  assert.equal(ownerRevoke.status, 204);
  assert.equal(stripeRevokeCount, 1);
});

function serviceBody(extra: { code: string; nonce: string; provider: "stripe" }) {
  return serviceEnvelope("site-1", extra.provider, { code: extra.code, nonce: extra.nonce });
}

test("configuration rejects short or swapped credentials", () => {
  const validEnv: NodeJS.ProcessEnv = {
    DATABASE_URL: "postgres://unused",
    BROKER_PUBLIC_URL: "https://connect.example.com",
    ADMITONE_CONNECT_SIGNING_SECRET: testSecret("broker"),
    STRIPE_CONNECT_CLIENT_ID: "ca_123456",
    STRIPE_PLATFORM_SECRET_KEY: "sk_test_123456",
    SQUARE_OAUTH_ENV: "sandbox",
    SQUARE_APP_ID: "sandbox-sq0idb-example",
    SQUARE_APP_SECRET: testSecret("square"),
  };

  assert.doesNotThrow(() => loadConfig(validEnv));
  assert.throws(
    () => loadConfig({ ...validEnv, STRIPE_CONNECT_CLIENT_ID: validEnv.STRIPE_PLATFORM_SECRET_KEY }),
    /STRIPE_CONNECT_CLIENT_ID/,
  );
  assert.throws(
    () => loadConfig({ ...validEnv, ADMITONE_CONNECT_SIGNING_SECRET: "too-short" }),
    /at least 32 characters/,
  );
  assert.throws(
    () => parseRegistry(JSON.stringify({
      client: { secret: "too-short", returnOrigin: "https://client.example.com" },
    })),
    /at least 32 characters/,
  );
});

function serviceEnvelope<T extends Record<string, unknown>>(
  siteId: string,
  provider: "stripe" | "square",
  fields: T,
  envelopeClientId = clientId,
) {
  const now = Math.floor(Date.now() / 1000);
  return {
    client_id: envelopeClientId,
    site_id: siteId,
    provider,
    iat: now,
    exp: now + 300,
    request_id: crypto.randomUUID().replaceAll("-", ""),
    ...fields,
  };
}

function assertString(value: string | null): string {
  assert.ok(value);
  return value;
}

function cookieHeader(response: Response): string {
  return assertString(response.headers.get("set-cookie")).split(";", 1)[0];
}

function testSecret(label: string): string {
  return `${label}-${"test-fixture-entropy-".repeat(2)}`;
}
