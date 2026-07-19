import { normalizeHttpsBaseUrl } from "./urls.js";

export type SquareOAuthEnv = "production" | "sandbox";

export interface AppConfig {
  port: number;
  databaseUrl: string;
  brokerPublicUrl: string;
  brokerSigningSecret: string;
  stripeConnectClientId: string;
  stripePlatformSecretKey: string;
  squareAppId: string;
  squareOAuthEnv: SquareOAuthEnv;
  squareApiVersion: string;
  squareOAuthScopes: string[];
  providerTimeoutMs: number;
}

const DEFAULT_SQUARE_SCOPES = [
  "MERCHANT_PROFILE_READ",
  "PAYMENTS_READ",
  "PAYMENTS_WRITE",
  "ORDERS_READ",
  "ORDERS_WRITE",
];

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const squareOAuthEnv = parseSquareOAuthEnv(env.SQUARE_OAUTH_ENV);
  return {
    port: parsePort(env.PORT),
    databaseUrl: requireEnv(env, "DATABASE_URL"),
    brokerPublicUrl: normalizeHttpsBaseUrl(requireEnv(env, "BROKER_PUBLIC_URL"), "BROKER_PUBLIC_URL", {
      allowLocalhostHttp: true,
    }),
    brokerSigningSecret: requireSecret(env, "ADMITONE_CONNECT_SIGNING_SECRET"),
    stripeConnectClientId: requirePattern(
      env,
      "STRIPE_CONNECT_CLIENT_ID",
      /^ca_[A-Za-z0-9]+$/,
      "a Stripe Connect client id beginning with ca_",
    ),
    stripePlatformSecretKey: requirePattern(
      env,
      "STRIPE_PLATFORM_SECRET_KEY",
      /^sk_(?:live|test)_[A-Za-z0-9]+$/,
      "a Stripe secret key beginning with sk_live_ or sk_test_",
    ),
    squareAppId: requirePattern(
      env,
      "SQUARE_APP_ID",
      squareOAuthEnv === "production"
        ? /^sq0idp-[A-Za-z0-9_-]+$/
        : /^sandbox-sq0idb-[A-Za-z0-9_-]+$/,
      squareOAuthEnv === "production"
        ? "a production Square application id beginning with sq0idp-"
        : "a sandbox Square application id beginning with sandbox-sq0idb-",
    ),
    squareOAuthEnv,
    squareApiVersion: env.SQUARE_API_VERSION?.trim() || "2025-12-17",
    squareOAuthScopes: parseScopes(env.SQUARE_OAUTH_SCOPES),
    providerTimeoutMs: parsePositiveInteger(env.PROVIDER_TIMEOUT_MS, 10_000, "PROVIDER_TIMEOUT_MS"),
  };
}

function parsePositiveInteger(raw: string | undefined, fallback: number, name: string): number {
  if (!raw || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 60_000) {
    throw new Error(`${name} must be an integer between 1 and 60000`);
  }
  return parsed;
}

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function requireSecret(env: NodeJS.ProcessEnv, name: string): string {
  const value = requireEnv(env, name);
  if (value.length < 32) {
    throw new Error(`${name} must be at least 32 characters`);
  }
  return value;
}

function requirePattern(
  env: NodeJS.ProcessEnv,
  name: string,
  pattern: RegExp,
  description: string,
): string {
  const value = requireEnv(env, name);
  if (!pattern.test(value)) {
    throw new Error(`${name} must be ${description}`);
  }
  return value;
}

function parsePort(raw: string | undefined): number {
  if (!raw || raw.trim() === "") return 8080;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  return parsed;
}

function parseSquareOAuthEnv(raw: string | undefined): SquareOAuthEnv {
  const value = raw?.trim() || "production";
  if (value === "production" || value === "sandbox") return value;
  throw new Error("SQUARE_OAUTH_ENV must be either production or sandbox");
}

function parseScopes(raw: string | undefined): string[] {
  if (!raw || raw.trim() === "") return DEFAULT_SQUARE_SCOPES;
  const scopes = raw.split(/\s+/).filter(Boolean);
  if (scopes.length === 0) return DEFAULT_SQUARE_SCOPES;
  return scopes;
}
