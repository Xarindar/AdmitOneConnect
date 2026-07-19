import "dotenv/config";

import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { type NextFunction, type Request, type Response } from "express";
import {
  type ArtifactStore,
  PostgresArtifactStore,
} from "./lib/artifact-store.js";
import { loadConfig, type AppConfig } from "./lib/config.js";
import { isRecord } from "./lib/objects.js";
import {
  buildAuthorizeUrl,
  createSquareCodeHandoff,
  exchangeStripeCode,
  isProvider,
  ProviderExchangeError,
  revokeProviderAccess,
  type Provider,
  type SquareHandoffData,
  type StripeHandoffData,
} from "./lib/providers.js";
import { rateLimit } from "./lib/rate-limit.js";
import {
  lookupClient,
  parseRegistry,
  type ClientEntry,
  type ClientRegistry,
} from "./lib/registry.js";
import {
  type ServiceRequestEnvelope,
  verifyServiceRequest,
} from "./lib/request-auth.js";
import { TOKEN_TYPES } from "./lib/token-types.js";
import { open, seal, sign, TokenError, verify } from "./lib/tokens.js";

const BROKER_STATE_TTL_SECONDS = 10 * 60;
const HANDOFF_TTL_SECONDS = 5 * 60;
const SERVICE_REQUEST_TTL_SECONDS = 5 * 60;

interface ClientStatePayload {
  typ: typeof TOKEN_TYPES.clientState;
  v: 1;
  siteId: string;
  provider: Provider;
  returnUrl: string;
  nonce: string;
  codeChallenge?: string;
  iat: number;
  exp: number;
}

interface BrokerStatePayload {
  typ: typeof TOKEN_TYPES.brokerState;
  v: 1;
  stateId: string;
  clientId: string;
  provider: Provider;
  clientState: ClientStatePayload;
  returnUrl: string;
  iat: number;
  exp: number;
}

interface HandoffPayload {
  typ: typeof TOKEN_TYPES.handoff;
  v: 1;
  clientId: string;
  provider: Provider;
  siteId: string;
  nonce: string;
  data: StripeHandoffData | SquareHandoffData;
  iat: number;
  exp: number;
}

interface HandoffRedeemBody extends ServiceRequestEnvelope {
  provider: Provider;
  code: string;
  nonce: string;
}

interface RevokeBody extends ServiceRequestEnvelope {
  provider: Provider;
  externalAccountId: string;
}

interface RawBodyRequest extends Request {
  rawBody?: string;
}

class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

type AsyncHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
) => Promise<void>;

export function createApp(
  config: AppConfig,
  registry: ClientRegistry,
  store: ArtifactStore,
): express.Express {
  const app = express();
  const providerCalls = new ProviderCallGuard(20, 5, 30_000);

  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(securityHeaders);
  app.use(rateLimit(store, { keyPrefix: "global", limit: 300, windowMs: 60_000 }));
  app.use(
    express.json({
      limit: "32kb",
      strict: true,
      verify: (req, _res, buffer) => {
        (req as RawBodyRequest).rawBody = buffer.toString("utf8");
      },
    }),
  );

  app.get(
    "/health",
    rateLimit(store, { keyPrefix: "health", limit: 60, windowMs: 60_000 }),
    asyncRoute(async (_req, res) => {
      await store.ping();
      res.json({ ok: true });
    }),
  );

  app.get(
    "/connect/:provider/start",
    rateLimit(store, { keyPrefix: "oauth-start", limit: 20, windowMs: 10 * 60_000 }),
    asyncRoute(async (req, res) => {
      const provider = parseProvider(req.params.provider);
      const clientId = requiredQuery(req, "client_id");
      const clientStateToken = requiredQuery(req, "state");
      const client = requireClient(registry, clientId);

      const clientState = validateClientState(
        verify<ClientStatePayload>(
          clientStateToken,
          client.secret,
          TOKEN_TYPES.clientState,
        ),
        provider,
      );
      assertAllowedReturnUrl(clientState.returnUrl, client.returnOrigin);

      const now = nowSeconds();
      const stateId = randomOpaqueValue();
      const brokerState: BrokerStatePayload = {
        typ: TOKEN_TYPES.brokerState,
        v: 1,
        stateId,
        clientId,
        provider,
        clientState,
        returnUrl: clientState.returnUrl,
        iat: now,
        exp: now + BROKER_STATE_TTL_SECONDS,
      };
      if (!(await store.registerState(stateId, brokerState.exp))) {
        throw new HttpError(503, "could not initialize OAuth state");
      }
      setBrokerStateCookie(res, config, provider, stateId);

      const redirectUrl = buildAuthorizeUrl(
        config,
        provider,
        sign(brokerState, config.brokerSigningSecret),
        clientState.codeChallenge,
      );
      res.redirect(302, redirectUrl);
    }),
  );

  app.get(
    "/connect/:provider/callback",
    rateLimit(store, { keyPrefix: "oauth-callback", limit: 30, windowMs: 10 * 60_000 }),
    asyncRoute(async (req, res) => {
      const provider = parseProvider(req.params.provider);
      const state = validateBrokerState(
        verify<BrokerStatePayload>(
          requiredQuery(req, "state"),
          config.brokerSigningSecret,
          TOKEN_TYPES.brokerState,
        ),
        provider,
      );
      const client = requireClient(registry, state.clientId);
      assertAllowedReturnUrl(state.returnUrl, client.returnOrigin);
      if (!hasValidBrokerStateCookie(req, config, provider, state.stateId)) {
        throw new HttpError(401, "OAuth callback did not originate from this browser");
      }
      clearBrokerStateCookie(res, config, provider);
      if (!(await store.consumeState(state.stateId))) {
        throw new HttpError(409, "OAuth callback has already been used");
      }

      const providerError = optionalQuery(req, "error");
      if (providerError) {
        redirectToClientError(
          res,
          state.returnUrl,
          provider,
          providerError === "access_denied" ? "access_denied" : "provider_error",
          "Provider authorization was not completed.",
        );
        return;
      }

      const code = requiredQuery(req, "code");
      const now = nowSeconds();
      let data: StripeHandoffData | SquareHandoffData;
      try {
        data = provider === "stripe"
          ? await providerCalls.run("stripe", () => exchangeStripeCode(config, code))
          : createSquareCodeHandoff(config, code);
      } catch (error) {
        logProviderFailure("token_exchange", provider, error);
        redirectToClientError(
          res,
          state.returnUrl,
          provider,
          "token_exchange_failed",
          "Unable to complete provider token exchange.",
        );
        return;
      }

      const handoff: HandoffPayload = {
        typ: TOKEN_TYPES.handoff,
        v: 1,
        clientId: state.clientId,
        provider,
        siteId: state.clientState.siteId,
        nonce: state.clientState.nonce,
        data,
        iat: now,
        exp: now + HANDOFF_TTL_SECONDS,
      };
      const opaqueCode = randomOpaqueValue();
      const stripeAccountId = provider === "stripe"
        ? (data as StripeHandoffData).stripeUserId
        : undefined;
      if (stripeAccountId) {
        await store.registerProviderOwnership(
          state.clientId,
          handoff.siteId,
          "stripe",
          stripeAccountId,
        );
      }
      try {
        await store.putHandoff(opaqueCode, {
          clientId: state.clientId,
          siteId: handoff.siteId,
          provider,
          nonce: handoff.nonce,
          sealedPayload: seal(
            handoff,
            config.brokerSigningSecret,
            TOKEN_TYPES.handoff,
          ),
          expiresAt: handoff.exp,
        });
      } catch (error) {
        if (stripeAccountId) {
          await store.removeProviderOwnership(
            state.clientId,
            handoff.siteId,
            "stripe",
            stripeAccountId,
          );
          await compensateStripeAuthorization(
            config,
            providerCalls,
            data as StripeHandoffData,
          );
        }
        throw error;
      }

      const redirectUrl = new URL(state.returnUrl);
      redirectUrl.searchParams.set("code", opaqueCode);
      res.redirect(302, redirectUrl.toString());
    }),
  );

  app.post(
    "/connect/handoff/redeem",
    rateLimit(store, { keyPrefix: "handoff-redeem", limit: 60, windowMs: 5 * 60_000 }),
    asyncRoute(async (req, res) => {
      const body = validateHandoffRedeemBody(req.body);
      await authenticateServiceRequest(req, body, registry, store);
      const record = await store.consumeHandoff(body.code, {
        clientId: body.client_id,
        siteId: body.site_id,
        provider: body.provider,
        nonce: body.nonce,
      });
      if (!record) throw new HttpError(409, "handoff is invalid, expired, or already used");

      const handoff = validateHandoff(
        open<HandoffPayload>(
          record.sealedPayload,
          config.brokerSigningSecret,
          TOKEN_TYPES.handoff,
        ),
        body,
      );
      res.json({ handoff });
    }),
  );

  app.post(
    "/connect/stripe/revoke",
    rateLimit(store, { keyPrefix: "provider-revoke", limit: 30, windowMs: 10 * 60_000 }),
    asyncRoute(async (req, res) => {
      const provider = "stripe" as const;
      const body = validateRevokeBody(req.body, provider);
      await authenticateServiceRequest(req, body, registry, store);
      const owned = await store.isProviderOwnedBy(
        body.client_id,
        body.site_id,
        provider,
        body.externalAccountId,
      );
      if (!owned) {
        if (Object.keys(registry).length !== 1) {
          throw new HttpError(403, "provider account is not owned by this client");
        }
        // Backward compatibility for the pre-ownership-map deployment. This is
        // safe only while the broker has exactly one registered client.
        await store.registerProviderOwnership(
          body.client_id,
          body.site_id,
          provider,
          body.externalAccountId,
        );
      }
      await providerCalls.run(provider, () =>
        revokeProviderAccess(config, provider, {
          externalAccountId: body.externalAccountId,
        }),
      );
      await store.removeProviderOwnership(
        body.client_id,
        body.site_id,
        provider,
        body.externalAccountId,
      );
      res.status(204).end();
    }),
  );

  app.use((req, _res, next) => {
    next(new HttpError(404, `route not found: ${req.method} ${req.path}`));
  });

  app.use(
    (
      error: unknown,
      _req: Request,
      res: Response,
      _next: NextFunction,
    ): void => {
      const status =
        error instanceof HttpError
          ? error.status
          : error instanceof TokenError
            ? 400
            : error instanceof ProviderExchangeError
              ? 502
              : readErrorStatus(error) ?? 500;
      const message =
        error instanceof TokenError
          ? "invalid or expired token"
          : error instanceof HttpError
            ? error.message
            : status < 500
              ? "malformed request"
              : "internal server error";

      res.status(status).json({
        error: errorCodeForStatus(status),
        message: status >= 500 ? "internal server error" : message,
      });

      if (status >= 500) {
        console.error("request failed", { name: errorName(error), status });
      }
    },
  );

  return app;
}

function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  next();
}

function brokerStateCookieName(provider: Provider): string {
  return `aoc_oauth_${provider}`;
}

function brokerStateCookieValue(stateId: string, secret: string): string {
  return crypto
    .createHmac("sha256", secret)
    .update(`admitone-browser-state-v1\0${stateId}`, "utf8")
    .digest("base64url");
}

function brokerStateCookieOptions(config: AppConfig, provider: Provider) {
  return {
    httpOnly: true,
    maxAge: BROKER_STATE_TTL_SECONDS * 1_000,
    path: `/connect/${provider}/callback`,
    sameSite: "lax" as const,
    secure: new URL(config.brokerPublicUrl).protocol === "https:",
  };
}

function setBrokerStateCookie(
  res: Response,
  config: AppConfig,
  provider: Provider,
  stateId: string,
): void {
  res.cookie(
    brokerStateCookieName(provider),
    brokerStateCookieValue(stateId, config.brokerSigningSecret),
    brokerStateCookieOptions(config, provider),
  );
}

function clearBrokerStateCookie(
  res: Response,
  config: AppConfig,
  provider: Provider,
): void {
  const { maxAge: _maxAge, ...options } = brokerStateCookieOptions(config, provider);
  res.clearCookie(brokerStateCookieName(provider), options);
}

function hasValidBrokerStateCookie(
  req: Request,
  config: AppConfig,
  provider: Provider,
  stateId: string,
): boolean {
  const name = brokerStateCookieName(provider);
  const rawCookie = req.header("cookie") ?? "";
  let candidate = "";
  for (const part of rawCookie.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      candidate = decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return false;
    }
    break;
  }
  const expected = brokerStateCookieValue(stateId, config.brokerSigningSecret);
  const candidateBuffer = Buffer.from(candidate, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  const comparable =
    candidateBuffer.length === expectedBuffer.length
      ? candidateBuffer
      : Buffer.alloc(expectedBuffer.length);
  return (
    crypto.timingSafeEqual(comparable, expectedBuffer) &&
    candidateBuffer.length === expectedBuffer.length
  );
}

async function authenticateServiceRequest<T extends ServiceRequestEnvelope>(
  req: Request,
  body: T,
  registry: ClientRegistry,
  store: ArtifactStore,
): Promise<ClientEntry> {
  validateServiceEnvelope(body);
  const client = requireClient(registry, body.client_id);
  const rawBody = (req as RawBodyRequest).rawBody ?? "";
  if (
    !verifyServiceRequest(
      req.method,
      req.path,
      rawBody,
      body,
      req.header("x-admitone-signature"),
      client.secret,
    )
  ) {
    throw new HttpError(401, "invalid request signature");
  }
  if (!(await store.registerRequest(body.client_id, body.request_id, body.exp))) {
    throw new HttpError(409, "request has already been used");
  }
  return client;
}

function validateServiceEnvelope(body: ServiceRequestEnvelope): void {
  if (
    typeof body.client_id !== "string" ||
    body.client_id.trim() === "" ||
    typeof body.site_id !== "string" ||
    body.site_id.trim() === "" ||
    typeof body.provider !== "string" ||
    typeof body.request_id !== "string" ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(body.request_id) ||
    !Number.isInteger(body.iat) ||
    !Number.isInteger(body.exp)
  ) {
    throw new HttpError(400, "malformed service request");
  }
  const now = nowSeconds();
  if (
    body.iat > now + 30 ||
    body.exp <= now ||
    body.exp <= body.iat ||
    body.exp - body.iat > SERVICE_REQUEST_TTL_SECONDS
  ) {
    throw new HttpError(401, "stale request signature");
  }
}

function validateHandoffRedeemBody(body: unknown): HandoffRedeemBody {
  if (!isRecord(body) || typeof body.provider !== "string" || !isProvider(body.provider)) {
    throw new HttpError(400, "malformed handoff request");
  }
  if (
    typeof body.code !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(body.code) ||
    typeof body.nonce !== "string" ||
    body.nonce.trim() === "" ||
    body.nonce.length > 128
  ) {
    throw new HttpError(400, "malformed handoff request");
  }
  return body as unknown as HandoffRedeemBody;
}

function validateRevokeBody(body: unknown, provider: Provider): RevokeBody {
  if (
    !isRecord(body) ||
    body.provider !== provider ||
    typeof body.externalAccountId !== "string" ||
    body.externalAccountId.trim() === "" ||
    body.externalAccountId.length > 255
  ) {
    throw new HttpError(400, "malformed revocation request");
  }
  return body as unknown as RevokeBody;
}

function validateHandoff(
  payload: HandoffPayload,
  request: HandoffRedeemBody,
): HandoffPayload {
  if (
    !isRecord(payload) ||
    payload.typ !== TOKEN_TYPES.handoff ||
    payload.v !== 1 ||
    payload.clientId !== request.client_id ||
    payload.siteId !== request.site_id ||
    payload.provider !== request.provider ||
    payload.nonce !== request.nonce ||
    !isRecord(payload.data)
  ) {
    throw new HttpError(401, "invalid handoff");
  }
  return payload;
}

async function compensateStripeAuthorization(
  config: AppConfig,
  guard: ProviderCallGuard,
  data: StripeHandoffData,
): Promise<void> {
  try {
    await guard.run("stripe", () =>
      revokeProviderAccess(config, "stripe", { externalAccountId: data.stripeUserId }),
    );
  } catch (error) {
    logProviderFailure("compensating_revoke", "stripe", error);
  }
}

class ProviderCallGuard {
  private active = 0;
  private readonly failures = new Map<Provider, { count: number; openUntil: number }>();

  constructor(
    private readonly maxConcurrent: number,
    private readonly failureThreshold: number,
    private readonly resetMs: number,
  ) {}

  async run<T>(provider: Provider, operation: () => Promise<T>): Promise<T> {
    const circuit = this.failures.get(provider);
    if (circuit && circuit.openUntil > Date.now()) {
      throw new HttpError(503, "provider service is temporarily unavailable");
    }
    if (this.active >= this.maxConcurrent) {
      throw new HttpError(503, "provider request capacity is temporarily exhausted");
    }
    this.active += 1;
    try {
      const result = await operation();
      this.failures.delete(provider);
      return result;
    } catch (error) {
      if (isTransientProviderFailure(error)) {
        const nextCount = (circuit?.count ?? 0) + 1;
        this.failures.set(provider, {
          count: nextCount,
          openUntil: nextCount >= this.failureThreshold ? Date.now() + this.resetMs : 0,
        });
      }
      throw error;
    } finally {
      this.active -= 1;
    }
  }
}

function isTransientProviderFailure(error: unknown): boolean {
  return !(error instanceof ProviderExchangeError) || !error.status || error.status >= 500;
}

function logProviderFailure(operation: string, provider: Provider, error: unknown): void {
  console.error("provider operation failed", {
    operation,
    provider,
    status: error instanceof ProviderExchangeError ? error.status : undefined,
    name: errorName(error),
  });
}

function asyncRoute(handler: AsyncHandler): express.RequestHandler {
  return (req, res, next) => {
    void handler(req, res, next).catch(next);
  };
}

function parseProvider(raw: string | undefined): Provider {
  if (!raw || !isProvider(raw)) throw new HttpError(404, "unknown provider");
  return raw;
}

function requiredQuery(req: Request, name: string): string {
  const value = optionalQuery(req, name);
  if (!value) throw new HttpError(400, `missing ${name}`);
  return value;
}

function optionalQuery(req: Request, name: string): string | undefined {
  const value = req.query[name];
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

function requireClient(registry: ClientRegistry, clientId: string): ClientEntry {
  const client = lookupClient(registry, clientId);
  if (!client) throw new HttpError(400, "unknown client_id");
  return client;
}

function validateClientState(
  payload: ClientStatePayload,
  expectedProvider: Provider,
): ClientStatePayload {
  if (
    !isRecord(payload) ||
    payload.typ !== TOKEN_TYPES.clientState ||
    payload.v !== 1 ||
    payload.provider !== expectedProvider
  ) {
    throw new HttpError(400, "client state is invalid");
  }
  for (const field of ["siteId", "returnUrl", "nonce"] as const) {
    if (typeof payload[field] !== "string" || payload[field].trim() === "") {
      throw new HttpError(400, "client state is invalid");
    }
  }
  if (
    expectedProvider === "square" &&
    (typeof payload.codeChallenge !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(payload.codeChallenge))
  ) {
    throw new HttpError(400, "Square client state requires a PKCE code challenge");
  }
  if (expectedProvider === "stripe" && payload.codeChallenge !== undefined) {
    throw new HttpError(400, "Stripe client state must not include a PKCE code challenge");
  }
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) {
    throw new HttpError(400, "client state is invalid");
  }
  const now = nowSeconds();
  if (payload.iat > now + 30 || payload.exp <= payload.iat || payload.exp - payload.iat > BROKER_STATE_TTL_SECONDS) {
    throw new HttpError(400, "client state is invalid");
  }
  return payload;
}

function validateBrokerState(
  payload: BrokerStatePayload,
  expectedProvider: Provider,
): BrokerStatePayload {
  if (
    !isRecord(payload) ||
    payload.typ !== TOKEN_TYPES.brokerState ||
    payload.v !== 1 ||
    payload.provider !== expectedProvider ||
    typeof payload.stateId !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(payload.stateId) ||
    typeof payload.clientId !== "string" ||
    typeof payload.returnUrl !== "string" ||
    !isRecord(payload.clientState)
  ) {
    throw new HttpError(400, "broker state is invalid");
  }
  validateClientState(payload.clientState, expectedProvider);
  return payload;
}

function assertAllowedReturnUrl(returnUrl: string, registeredOrigin: string): void {
  let parsed: URL;
  try {
    parsed = new URL(returnUrl);
  } catch {
    throw new HttpError(400, "returnUrl must be an absolute URL");
  }
  if (parsed.origin !== registeredOrigin || parsed.username || parsed.password) {
    throw new HttpError(400, "returnUrl origin is not registered for this client");
  }
}

function redirectToClientError(
  res: Response,
  returnUrl: string,
  provider: Provider,
  error: string,
  description: string,
): void {
  const redirectUrl = new URL(returnUrl);
  redirectUrl.searchParams.set("error", error);
  redirectUrl.searchParams.set("provider", provider);
  redirectUrl.searchParams.set("error_description", description);
  res.redirect(302, redirectUrl.toString());
}

function randomOpaqueValue(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function errorCodeForStatus(status: number): string {
  if (status === 401) return "unauthorized";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "internal_server_error";
  return "bad_request";
}

function readErrorStatus(error: unknown): number | undefined {
  if (!isRecord(error) || typeof error.status !== "number") return undefined;
  return error.status >= 400 && error.status < 600 ? error.status : undefined;
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "UnknownError";
}

function startupErrorDetail(error: unknown): string {
  if (!(error instanceof Error)) return "initialization failed";
  const safeConfigurationPrefixes = [
    "PORT ",
    "DATABASE_URL ",
    "BROKER_PUBLIC_URL ",
    "ADMITONE_CONNECT_SIGNING_SECRET ",
    "ADMITONE_CONNECT_CLIENTS ",
    "STRIPE_CONNECT_CLIENT_ID ",
    "STRIPE_PLATFORM_SECRET_KEY ",
    "SQUARE_APP_ID ",
    "SQUARE_OAUTH_ENV ",
    "PROVIDER_TIMEOUT_MS ",
  ];
  return safeConfigurationPrefixes.some((prefix) => error.message.startsWith(prefix))
    ? error.message
    : "initialization failed";
}

async function main(): Promise<void> {
  const config = loadConfig();
  const registry = parseRegistry(process.env.ADMITONE_CONNECT_CLIENTS);
  const store = new PostgresArtifactStore(config.databaseUrl);
  await store.initialize();
  const app = createApp(config, registry, store);

  const server = app.listen(config.port, () => {
    console.log(`AdmitOne Connect listening on :${config.port}`);
  });
  server.headersTimeout = 15_000;
  server.requestTimeout = 20_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 1_000;

  const shutdown = () => {
    server.close(() => {
      void store.close().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  void main().catch((error) => {
    console.error("AdmitOne Connect failed to start", {
      detail: startupErrorDetail(error),
      name: errorName(error),
    });
    process.exit(1);
  });
}
