import "dotenv/config";

import { fileURLToPath } from "node:url";
import express, { type NextFunction, type Request, type Response } from "express";
import { loadConfig, type AppConfig } from "./lib/config.js";
import {
  buildAuthorizeUrl,
  exchangeSquareCode,
  exchangeStripeCode,
  isProvider,
  ProviderExchangeError,
  refreshSquareToken,
  type SquareHandoffData,
  type SquareRefreshData,
  type Provider,
} from "./lib/providers.js";
import {
  lookupClient,
  parseRegistry,
  type ClientEntry,
  type ClientRegistry,
} from "./lib/registry.js";
import { isRecord } from "./lib/objects.js";
import { verifyRawBodySignature } from "./lib/signatures.js";
import { TOKEN_TYPES } from "./lib/token-types.js";
import { open, seal, sign, TokenError, verify } from "./lib/tokens.js";

const BROKER_STATE_TTL_SECONDS = 10 * 60;
const HANDOFF_TTL_SECONDS = 5 * 60;
const SIGNED_REFRESH_WINDOW_SECONDS = 5 * 60;
const SQUARE_REFRESH_HANDLE_TTL_SECONDS = 365 * 24 * 60 * 60;

interface ClientStatePayload {
  typ: typeof TOKEN_TYPES.clientState;
  v: 1;
  siteId: string;
  provider: Provider;
  returnUrl: string;
  nonce: string;
  iat: number;
  exp: number;
}

interface BrokerStatePayload {
  typ: typeof TOKEN_TYPES.brokerState;
  v: 1;
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
  provider: Provider;
  siteId: string;
  nonce: string;
  data: unknown;
  iat: number;
  exp: number;
}

interface SquareRefreshTokenPayload {
  typ: typeof TOKEN_TYPES.squareRefresh;
  v: 1;
  provider: "square";
  clientId: string;
  merchantId: string;
  refreshToken: string;
  iat: number;
  exp: number;
}

interface SquareRefreshBody {
  client_id: string;
  refreshToken: string;
  timestamp: number;
  nonce: string;
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

export function createApp(config: AppConfig, registry: ClientRegistry): express.Express {
  const app = express();
  const usedRefreshNonces = new Map<string, number>();

  app.disable("x-powered-by");
  app.use(
    express.json({
      limit: "64kb",
      verify: (req, _res, buffer) => {
        (req as RawBodyRequest).rawBody = buffer.toString("utf8");
      },
    }),
  );

  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.get(
    "/connect/:provider/start",
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
      const brokerState: BrokerStatePayload = {
        typ: TOKEN_TYPES.brokerState,
        v: 1,
        clientId,
        provider,
        clientState,
        returnUrl: clientState.returnUrl,
        iat: now,
        exp: now + BROKER_STATE_TTL_SECONDS,
      };

      const redirectUrl = buildAuthorizeUrl(
        config,
        provider,
        sign(brokerState, config.brokerSigningSecret),
      );

      res.redirect(302, redirectUrl);
    }),
  );

  app.get(
    "/connect/:provider/callback",
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

      const providerError = optionalQuery(req, "error");
      if (providerError) {
        redirectToClientError(
          res,
          state.returnUrl,
          provider,
          providerError,
          "Provider authorization was not completed.",
        );
        return;
      }

      const code = requiredQuery(req, "code");
      const now = nowSeconds();
      let data: unknown;
      try {
        data = await exchangeAndPrepareHandoffData(
          config,
          provider,
          code,
          client,
          state.clientId,
          now,
        );
      } catch (error) {
        console.error("Provider token exchange failed", error);
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
        provider,
        siteId: state.clientState.siteId,
        nonce: state.clientState.nonce,
        data,
        iat: now,
        exp: now + HANDOFF_TTL_SECONDS,
      };

      const redirectUrl = new URL(state.returnUrl);
      redirectUrl.searchParams.set(
        "handoff",
        seal(handoff, client.secret, TOKEN_TYPES.handoff),
      );
      res.redirect(302, redirectUrl.toString());
    }),
  );

  app.post(
    "/connect/square/refresh",
    asyncRoute(async (req, res) => {
      const body = validateSquareRefreshBody(req.body);
      const client = requireClient(registry, body.client_id);
      const rawBody = (req as RawBodyRequest).rawBody ?? "";
      const signatureHeader = req.header("x-admitone-signature");

      if (!verifyRawBodySignature(rawBody, signatureHeader, client.secret)) {
        throw new HttpError(401, "invalid request signature");
      }

      assertFreshRefreshRequest(body, usedRefreshNonces);

      const refreshHandle = validateSquareRefreshToken(
        open<SquareRefreshTokenPayload>(
          body.refreshToken,
          client.secret,
          TOKEN_TYPES.squareRefresh,
        ),
        body.client_id,
      );

      const refreshed = await refreshSquareToken(config, refreshHandle.refreshToken);
      res.json(
        sealSquareRefreshResponse(
          refreshed,
          client,
          body.client_id,
          refreshHandle.merchantId,
          nowSeconds(),
        ),
      );
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
          : error instanceof Error
            ? error.message
            : "internal server error";

      res.status(status).json({
        error: errorCodeForStatus(status),
        message: status >= 500 ? "internal server error" : message,
      });

      if (status >= 500) {
        console.error(error);
      }
    },
  );

  return app;
}

function asyncRoute(handler: AsyncHandler): express.RequestHandler {
  return (req, res, next) => {
    void handler(req, res, next).catch(next);
  };
}

function parseProvider(raw: string | undefined): Provider {
  if (!raw || !isProvider(raw)) {
    throw new HttpError(404, "unknown provider");
  }
  return raw;
}

function requiredQuery(req: Request, name: string): string {
  const value = optionalQuery(req, name);
  if (!value) {
    throw new HttpError(400, `missing ${name}`);
  }
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
  if (!client) {
    throw new HttpError(400, "unknown client_id");
  }
  return client;
}

async function exchangeAndPrepareHandoffData(
  config: AppConfig,
  provider: Provider,
  code: string,
  client: ClientEntry,
  clientId: string,
  now: number,
): Promise<unknown> {
  switch (provider) {
    case "stripe":
      return exchangeStripeCode(config, code);
    case "square":
      return sealSquareHandoffData(
        await exchangeSquareCode(config, code),
        client,
        clientId,
        now,
      );
    default:
      return assertNever(provider);
  }
}

function sealSquareHandoffData(
  data: SquareHandoffData,
  client: ClientEntry,
  clientId: string,
  now: number,
): SquareHandoffData {
  return {
    ...data,
    refreshToken: sealSquareRefreshToken(
      data.refreshToken,
      client,
      clientId,
      data.merchantId,
      now,
    ),
  };
}

function sealSquareRefreshResponse(
  data: SquareRefreshData,
  client: ClientEntry,
  clientId: string,
  merchantId: string,
  now: number,
): SquareRefreshData {
  return {
    ...data,
    refreshToken: sealSquareRefreshToken(
      data.refreshToken,
      client,
      clientId,
      merchantId,
      now,
    ),
  };
}

function sealSquareRefreshToken(
  refreshToken: string,
  client: ClientEntry,
  clientId: string,
  merchantId: string,
  now: number,
): string {
  const payload: SquareRefreshTokenPayload = {
    typ: TOKEN_TYPES.squareRefresh,
    v: 1,
    provider: "square",
    clientId,
    merchantId,
    refreshToken,
    iat: now,
    exp: now + SQUARE_REFRESH_HANDLE_TTL_SECONDS,
  };

  return seal(payload, client.secret, TOKEN_TYPES.squareRefresh);
}

function validateClientState(
  payload: ClientStatePayload,
  expectedProvider: Provider,
): ClientStatePayload {
  if (!isRecord(payload)) {
    throw new HttpError(400, "client state must be an object");
  }
  if (payload.v !== 1) {
    throw new HttpError(400, "unsupported client state version");
  }
  if (payload.typ !== TOKEN_TYPES.clientState) {
    throw new HttpError(400, "client state type mismatch");
  }
  if (payload.provider !== expectedProvider) {
    throw new HttpError(400, "client state provider mismatch");
  }
  for (const field of ["siteId", "returnUrl", "nonce"] as const) {
    if (typeof payload[field] !== "string" || payload[field].trim() === "") {
      throw new HttpError(400, `client state missing ${field}`);
    }
  }
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) {
    throw new HttpError(400, "client state missing timestamp");
  }
  return payload;
}

function validateBrokerState(
  payload: BrokerStatePayload,
  expectedProvider: Provider,
): BrokerStatePayload {
  if (!isRecord(payload)) {
    throw new HttpError(400, "broker state must be an object");
  }
  if (
    payload.typ !== TOKEN_TYPES.brokerState ||
    payload.v !== 1 ||
    payload.provider !== expectedProvider
  ) {
    throw new HttpError(400, "broker state provider mismatch");
  }
  if (
    typeof payload.clientId !== "string" ||
    typeof payload.returnUrl !== "string" ||
    !isRecord(payload.clientState)
  ) {
    throw new HttpError(400, "broker state malformed");
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

  if (parsed.origin !== registeredOrigin) {
    throw new HttpError(400, "returnUrl origin is not registered for this client");
  }
}

function validateSquareRefreshBody(body: unknown): SquareRefreshBody {
  if (!isRecord(body)) {
    throw new HttpError(400, "request body must be JSON");
  }
  const clientId = body.client_id;
  const refreshToken = body.refreshToken;
  const timestamp = body.timestamp;
  const nonce = body.nonce;

  if (typeof clientId !== "string" || clientId.trim() === "") {
    throw new HttpError(400, "missing client_id");
  }
  if (typeof refreshToken !== "string" || refreshToken.trim() === "") {
    throw new HttpError(400, "missing refreshToken");
  }
  if (typeof timestamp !== "number" || !Number.isInteger(timestamp)) {
    throw new HttpError(400, "missing timestamp");
  }
  if (typeof nonce !== "string" || nonce.trim() === "") {
    throw new HttpError(400, "missing nonce");
  }
  if (nonce.length > 128) {
    throw new HttpError(400, "nonce is too long");
  }
  return {
    client_id: clientId,
    refreshToken,
    timestamp,
    nonce,
  };
}

function assertFreshRefreshRequest(
  body: SquareRefreshBody,
  usedRefreshNonces: Map<string, number>,
): void {
  const now = nowSeconds();
  pruneExpiredNonces(usedRefreshNonces, now);

  if (Math.abs(now - body.timestamp) > SIGNED_REFRESH_WINDOW_SECONDS) {
    throw new HttpError(401, "stale request signature");
  }

  const nonceKey = `${body.client_id}:${body.nonce}`;
  if (usedRefreshNonces.has(nonceKey)) {
    throw new HttpError(401, "replayed request signature");
  }
  usedRefreshNonces.set(nonceKey, now + SIGNED_REFRESH_WINDOW_SECONDS);
}

function pruneExpiredNonces(usedRefreshNonces: Map<string, number>, now: number): void {
  for (const [nonceKey, expiresAt] of usedRefreshNonces) {
    if (expiresAt <= now) {
      usedRefreshNonces.delete(nonceKey);
    }
  }
}

function validateSquareRefreshToken(
  payload: SquareRefreshTokenPayload,
  clientId: string,
): SquareRefreshTokenPayload {
  if (
    !isRecord(payload) ||
    payload.typ !== TOKEN_TYPES.squareRefresh ||
    payload.v !== 1 ||
    payload.provider !== "square" ||
    payload.clientId !== clientId ||
    typeof payload.merchantId !== "string" ||
    payload.merchantId.trim() === "" ||
    typeof payload.refreshToken !== "string" ||
    payload.refreshToken.trim() === "" ||
    !Number.isInteger(payload.iat) ||
    !Number.isInteger(payload.exp)
  ) {
    throw new HttpError(401, "invalid refresh token");
  }

  return payload;
}

function redirectToClientError(
  res: Response,
  returnUrl: string,
  provider: Provider,
  error: string,
  description: string | undefined,
): void {
  const redirectUrl = new URL(returnUrl);
  redirectUrl.searchParams.set("error", error);
  redirectUrl.searchParams.set("provider", provider);
  if (description) {
    redirectUrl.searchParams.set("error_description", description.slice(0, 500));
  }
  res.redirect(302, redirectUrl.toString());
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function errorCodeForStatus(status: number): string {
  if (status === 401) return "unauthorized";
  if (status === 404) return "not_found";
  if (status >= 500) return "internal_server_error";
  return "bad_request";
}

function readErrorStatus(error: unknown): number | undefined {
  if (!isRecord(error) || typeof error.status !== "number") return undefined;
  return error.status >= 400 && error.status < 600 ? error.status : undefined;
}

function assertNever(value: never): never {
  throw new Error(`unsupported provider: ${String(value)}`);
}

function main(): void {
  const config = loadConfig();
  const registry = parseRegistry(process.env.ADMITONE_CONNECT_CLIENTS);
  const app = createApp(config, registry);

  app.listen(config.port, () => {
    console.log(`AdmitOne Connect listening on :${config.port}`);
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
