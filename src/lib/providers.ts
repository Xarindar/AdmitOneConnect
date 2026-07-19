import type { AppConfig, SquareOAuthEnv } from "./config.js";
import { isRecord } from "./objects.js";

export type Provider = "stripe" | "square";

export interface StripeHandoffData {
  accessToken: string;
  refreshToken: string;
  stripeUserId: string;
  livemode: boolean;
  scope: string;
}

export interface SquareHandoffData {
  authorizationCode: string;
  clientId: string;
  redirectUri: string;
  environment: SquareOAuthEnv;
  squareVersion: string;
}

export interface ProviderRevocationInput {
  externalAccountId: string;
}

export class ProviderExchangeError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
  }
}

export function isProvider(value: string): value is Provider {
  return value === "stripe" || value === "square";
}

export function providerCallbackUrl(config: AppConfig, provider: Provider): string {
  return `${config.brokerPublicUrl}/connect/${provider}/callback`;
}

export function buildAuthorizeUrl(
  config: AppConfig,
  provider: Provider,
  brokerState: string,
  squareCodeChallenge?: string,
): string {
  return provider === "stripe"
    ? buildStripeAuthorizeUrl(config, brokerState)
    : buildSquareAuthorizeUrl(config, brokerState, squareCodeChallenge);
}

function buildStripeAuthorizeUrl(config: AppConfig, brokerState: string): string {
  const url = new URL("https://connect.stripe.com/oauth/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.stripeConnectClientId);
  url.searchParams.set("scope", "read_write");
  url.searchParams.set("redirect_uri", providerCallbackUrl(config, "stripe"));
  url.searchParams.set("state", brokerState);
  return url.toString();
}

function buildSquareAuthorizeUrl(
  config: AppConfig,
  brokerState: string,
  codeChallenge?: string,
): string {
  if (!codeChallenge || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
    throw new Error("Square PKCE code challenge is required");
  }
  const url = new URL(`${squareBaseUrl(config.squareOAuthEnv)}/oauth2/authorize`);
  url.searchParams.set("client_id", config.squareAppId);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("redirect_uri", providerCallbackUrl(config, "square"));
  url.searchParams.set("scope", config.squareOAuthScopes.join(" "));
  url.searchParams.set("state", brokerState);
  if (config.squareOAuthEnv === "production") {
    url.searchParams.set("session", "false");
  }
  return url.toString();
}

export async function exchangeStripeCode(
  config: AppConfig,
  code: string,
): Promise<StripeHandoffData> {
  const params = new URLSearchParams({
    client_secret: config.stripePlatformSecretKey,
    code,
    grant_type: "authorization_code",
  });

  const response = await fetch("https://connect.stripe.com/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: params,
    signal: AbortSignal.timeout(config.providerTimeoutMs),
  });

  const body = await parseProviderJson(response);
  if (!response.ok) {
    throw new ProviderExchangeError(
      providerErrorMessage("Stripe token exchange failed", body),
      response.status,
    );
  }

  const accessToken = readString(body, "access_token");
  const refreshToken = readOptionalString(body, "refresh_token");
  const stripeUserId = readString(body, "stripe_user_id");
  const scope = readString(body, "scope");
  const livemode = readBoolean(body, "livemode");
  const expectedLivemode = config.stripePlatformSecretKey.startsWith("sk_live_");
  if (livemode !== expectedLivemode) {
    throw new ProviderExchangeError("Stripe token mode does not match the configured platform key");
  }
  if (scope !== "read_write") {
    throw new ProviderExchangeError("Stripe did not grant the required read_write scope");
  }

  return { accessToken, refreshToken, stripeUserId, livemode, scope };
}

export function createSquareCodeHandoff(
  config: AppConfig,
  authorizationCode: string,
): SquareHandoffData {
  return {
    authorizationCode,
    clientId: config.squareAppId,
    redirectUri: providerCallbackUrl(config, "square"),
    environment: config.squareOAuthEnv,
    squareVersion: config.squareApiVersion,
  };
}

export async function revokeProviderAccess(
  config: AppConfig,
  provider: Provider,
  input: ProviderRevocationInput,
): Promise<void> {
  if (provider !== "stripe") {
    throw new ProviderExchangeError("Square PKCE access must be revoked by the seller");
  }
  await revokeStripeAccess(config, input.externalAccountId);
}

async function revokeStripeAccess(config: AppConfig, stripeUserId: string): Promise<void> {
  const body = new URLSearchParams({
    client_id: config.stripeConnectClientId,
    stripe_user_id: stripeUserId,
  });
  const response = await fetch("https://connect.stripe.com/oauth/deauthorize", {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${config.stripePlatformSecretKey}:`).toString("base64")}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
    signal: AbortSignal.timeout(config.providerTimeoutMs),
  });
  const parsed = await parseProviderJson(response);
  if (!response.ok || !isRecord(parsed) || parsed.stripe_user_id !== stripeUserId) {
    throw new ProviderExchangeError(
      providerErrorMessage("Stripe deauthorization failed", parsed),
      response.status,
    );
  }
}

function squareBaseUrl(env: SquareOAuthEnv): string {
  return env === "sandbox"
    ? "https://connect.squareupsandbox.com"
    : "https://connect.squareup.com";
}

async function parseProviderJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim() === "") return {};
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

function providerErrorMessage(prefix: string, body: unknown): string {
  if (!isRecord(body)) return prefix;

  const errorDescription = body.error_description;
  if (typeof errorDescription === "string" && errorDescription.trim() !== "") {
    return `${prefix}: ${errorDescription}`;
  }

  const errors = body.errors;
  if (Array.isArray(errors) && errors.length > 0) {
    const first = errors[0];
    if (isRecord(first) && typeof first.detail === "string") {
      return `${prefix}: ${first.detail}`;
    }
  }

  const error = body.error;
  if (typeof error === "string" && error.trim() !== "") {
    return `${prefix}: ${error}`;
  }

  return prefix;
}

function readString(body: unknown, field: string): string {
  if (isRecord(body) && typeof body[field] === "string" && body[field] !== "") {
    return body[field];
  }
  throw new ProviderExchangeError(`Provider response missing ${field}`);
}

function readOptionalString(body: unknown, field: string): string {
  if (!isRecord(body) || body[field] === undefined || body[field] === null) return "";
  if (typeof body[field] === "string") return body[field];
  throw new ProviderExchangeError(`Provider response has invalid ${field}`);
}

function readBoolean(body: unknown, field: string): boolean {
  if (isRecord(body) && typeof body[field] === "boolean") {
    return body[field];
  }
  throw new ProviderExchangeError(`Provider response missing ${field}`);
}

