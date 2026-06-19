import type { AppConfig, SquareOAuthEnv } from "./config.js";

export type Provider = "stripe" | "square";

export interface StripeHandoffData {
  accessToken: string;
  refreshToken: string;
  stripeUserId: string;
  livemode: boolean;
  scope: string;
}

export interface SquareHandoffData {
  accessToken: string;
  refreshToken: string;
  merchantId: string;
  expiresAt: string;
  environment: SquareOAuthEnv;
}

export interface SquareRefreshData {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
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
): string {
  if (provider === "stripe") {
    const url = new URL("https://connect.stripe.com/oauth/authorize");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.stripeConnectClientId);
    url.searchParams.set("scope", "read_write");
    url.searchParams.set("redirect_uri", providerCallbackUrl(config, provider));
    url.searchParams.set("state", brokerState);
    return url.toString();
  }

  const url = new URL(`${squareBaseUrl(config.squareOAuthEnv)}/oauth2/authorize`);
  url.searchParams.set("client_id", config.squareAppId);
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
  });

  const body = await parseProviderJson(response);
  if (!response.ok) {
    throw new ProviderExchangeError(
      providerErrorMessage("Stripe token exchange failed", body),
      response.status,
    );
  }

  const accessToken = readString(body, "access_token");
  const refreshToken = readString(body, "refresh_token");
  const stripeUserId = readString(body, "stripe_user_id");
  const scope = readString(body, "scope");
  const livemode = readBoolean(body, "livemode");

  return { accessToken, refreshToken, stripeUserId, livemode, scope };
}

export async function exchangeSquareCode(
  config: AppConfig,
  code: string,
): Promise<SquareHandoffData> {
  const response = await fetch(`${squareBaseUrl(config.squareOAuthEnv)}/oauth2/token`, {
    method: "POST",
    headers: squareJsonHeaders(config),
    body: JSON.stringify({
      client_id: config.squareAppId,
      client_secret: config.squareAppSecret,
      code,
      grant_type: "authorization_code",
    }),
  });

  const body = await parseProviderJson(response);
  if (!response.ok) {
    throw new ProviderExchangeError(
      providerErrorMessage("Square token exchange failed", body),
      response.status,
    );
  }

  return {
    accessToken: readString(body, "access_token"),
    refreshToken: readString(body, "refresh_token"),
    merchantId: readString(body, "merchant_id"),
    expiresAt: readString(body, "expires_at"),
    environment: config.squareOAuthEnv,
  };
}

export async function refreshSquareToken(
  config: AppConfig,
  refreshToken: string,
): Promise<SquareRefreshData> {
  const response = await fetch(`${squareBaseUrl(config.squareOAuthEnv)}/oauth2/token`, {
    method: "POST",
    headers: squareJsonHeaders(config),
    body: JSON.stringify({
      client_id: config.squareAppId,
      client_secret: config.squareAppSecret,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });

  const body = await parseProviderJson(response);
  if (!response.ok) {
    throw new ProviderExchangeError(
      providerErrorMessage("Square refresh failed", body),
      response.status,
    );
  }

  return {
    accessToken: readString(body, "access_token"),
    refreshToken: readString(body, "refresh_token"),
    expiresAt: readString(body, "expires_at"),
  };
}

function squareBaseUrl(env: SquareOAuthEnv): string {
  return env === "sandbox"
    ? "https://connect.squareupsandbox.com"
    : "https://connect.squareup.com";
}

function squareJsonHeaders(config: AppConfig): Record<string, string> {
  return {
    "content-type": "application/json",
    "square-version": config.squareApiVersion,
  };
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

function readBoolean(body: unknown, field: string): boolean {
  if (isRecord(body) && typeof body[field] === "boolean") {
    return body[field];
  }
  throw new ProviderExchangeError(`Provider response missing ${field}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
