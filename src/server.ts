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
  type Provider,
} from "./lib/providers.js";
import {
  lookupClient,
  parseRegistry,
  type ClientEntry,
  type ClientRegistry,
} from "./lib/registry.js";
import { verifyRawBodySignature } from "./lib/signatures.js";
import { sign, TokenError, verify } from "./lib/tokens.js";

interface ClientStatePayload {
  v: 1;
  siteId: string;
  provider: Provider;
  returnUrl: string;
  nonce: string;
  iat: number;
  exp: number;
}

interface BrokerStatePayload {
  v: 1;
  clientId: string;
  provider: Provider;
  clientState: ClientStatePayload;
  returnUrl: string;
  iat: number;
  exp: number;
}

interface HandoffPayload {
  v: 1;
  provider: Provider;
  siteId: string;
  nonce: string;
  data: unknown;
  iat: number;
  exp: number;
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
        verify<ClientStatePayload>(clientStateToken, client.secret),
        provider,
      );
      assertAllowedReturnUrl(clientState.returnUrl, client.returnOrigin);

      const now = nowSeconds();
      const brokerState: BrokerStatePayload = {
        v: 1,
        clientId,
        provider,
        clientState,
        returnUrl: clientState.returnUrl,
        iat: now,
        exp: now + 10 * 60,
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
          optionalQuery(req, "error_description"),
        );
        return;
      }

      const code = requiredQuery(req, "code");
      let data: unknown;
      try {
        data =
          provider === "stripe"
            ? await exchangeStripeCode(config, code)
            : await exchangeSquareCode(config, code);
      } catch (error) {
        redirectToClientError(
          res,
          state.returnUrl,
          provider,
          "token_exchange_failed",
          error instanceof Error ? error.message : undefined,
        );
        return;
      }

      const now = nowSeconds();
      const handoff: HandoffPayload = {
        v: 1,
        provider,
        siteId: state.clientState.siteId,
        nonce: state.clientState.nonce,
        data,
        iat: now,
        exp: now + 5 * 60,
      };

      const redirectUrl = new URL(state.returnUrl);
      redirectUrl.searchParams.set("handoff", sign(handoff, client.secret));
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

      const refreshed = await refreshSquareToken(config, body.refreshToken);
      res.json(refreshed);
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
  if (payload.v !== 1 || payload.provider !== expectedProvider) {
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

function validateSquareRefreshBody(body: unknown): {
  client_id: string;
  refreshToken: string;
} {
  if (!isRecord(body)) {
    throw new HttpError(400, "request body must be JSON");
  }
  if (typeof body.client_id !== "string" || body.client_id.trim() === "") {
    throw new HttpError(400, "missing client_id");
  }
  if (typeof body.refreshToken !== "string" || body.refreshToken.trim() === "") {
    throw new HttpError(400, "missing refreshToken");
  }
  return { client_id: body.client_id, refreshToken: body.refreshToken };
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
