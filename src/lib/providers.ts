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

type ProviderHandoffData = StripeHandoffData | SquareHandoffData;

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
  return authorizeUrlBuilders[provider](config, brokerState);
}

export async function exchangeProviderCode(
  config: AppConfig,
  provider: Provider,
  code: string,
): Promise<ProviderHandoffData> {
  return exchangeCodeHandlers[provider](config, code);
}

const authorizeUrlBuilders = {
  stripe: buildStripeAuthorizeUrl,
  square: buildSquareAuthorizeUrl,
} satisfies Record<Provider, (config: AppConfig, brokerState: string) => string>;

const exchangeCodeHandlers = {
  stripe: exchangeStripeCode,
  square: exchangeSquareCode,
} satisfies Record<
  Provider,
  (config: AppConfig, code: string) => Promise<ProviderHandoffData>
>;

function buildStripeAuthorizeUrl(config: AppConfig, brokerState: string): string {
  const url = new URL("https://connect.stripe.com/oauth/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.stripeConnectClientId);
  url.searchParams.set("scope", "read_write");
  url.searchParams.set("redirect_uri", providerCallbackUrl(config, "stripe"));
  url.searchParams.set("state", brokerState);
  return url.toString();
}

function buildSquareAuthorizeUrl(config: AppConfig, brokerState: string): string {
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
  const body = await squareTokenRequest(
    config,
    {
      code,
      grant_type: "authorization_code",
    },
    "Square token exchange failed",
  );

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
  const body = await squareTokenRequest(
    config,
    {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    },
    "Square refresh failed",
  );

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

async function squareTokenRequest(
  config: AppConfig,
  fields: Record<string, string>,
  errorPrefix: string,
): Promise<unknown> {
  const response = await fetch(`${squareBaseUrl(config.squareOAuthEnv)}/oauth2/token`, {
    method: "POST",
    headers: squareJsonHeaders(config),
    body: JSON.stringify({
      client_id: config.squareAppId,
      client_secret: config.squareAppSecret,
      ...fields,
    }),
  });

  const body = await parseProviderJson(response);
  if (!response.ok) {
    throw new ProviderExchangeError(providerErrorMessage(errorPrefix, body), response.status);
  }

  return body;
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

