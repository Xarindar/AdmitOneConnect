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
  squareAppSecret: string;
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
  return {
    port: parsePort(env.PORT),
    databaseUrl: requireEnv(env, "DATABASE_URL"),
    brokerPublicUrl: normalizeHttpsBaseUrl(requireEnv(env, "BROKER_PUBLIC_URL"), "BROKER_PUBLIC_URL", {
      allowLocalhostHttp: true,
    }),
    brokerSigningSecret: requireEnv(env, "ADMITONE_CONNECT_SIGNING_SECRET"),
    stripeConnectClientId: requireEnv(env, "STRIPE_CONNECT_CLIENT_ID"),
    stripePlatformSecretKey: requireEnv(env, "STRIPE_PLATFORM_SECRET_KEY"),
    squareAppId: requireEnv(env, "SQUARE_APP_ID"),
    squareAppSecret: requireEnv(env, "SQUARE_APP_SECRET"),
    squareOAuthEnv: parseSquareOAuthEnv(env.SQUARE_OAUTH_ENV),
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
