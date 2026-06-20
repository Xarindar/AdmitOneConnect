import { isRecord } from "./objects.js";
import { normalizeHttpsOrigin } from "./urls.js";

export interface ClientEntry {
  secret: string;
  returnOrigin: string;
}

export type ClientRegistry = Record<string, ClientEntry>;

/**
 * Parse the client registry from the ADMITONE_CONNECT_CLIENTS env var (JSON).
 * Shape: { "<clientId>": { "secret": "...", "returnOrigin": "https://client.example.com" } }
 */
export function parseRegistry(raw: string | undefined): ClientRegistry {
  if (!raw || raw.trim() === "") {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("ADMITONE_CONNECT_CLIENTS is not valid JSON");
  }

  if (!isRecord(parsed)) {
    throw new Error("ADMITONE_CONNECT_CLIENTS must be a JSON object");
  }

  const registry: ClientRegistry = {};
  for (const [clientId, entry] of Object.entries(parsed)) {
    if (
      !isRecord(entry) ||
      typeof entry.secret !== "string" ||
      typeof entry.returnOrigin !== "string"
    ) {
      throw new Error(
        `ADMITONE_CONNECT_CLIENTS entry "${clientId}" must have string "secret" and "returnOrigin"`,
      );
    }
    const { secret, returnOrigin } = entry;
    if (secret.trim() === "") {
      throw new Error(`ADMITONE_CONNECT_CLIENTS entry "${clientId}" has an empty secret`);
    }
    registry[clientId] = {
      secret,
      returnOrigin: normalizeReturnOrigin(returnOrigin, clientId),
    };
  }

  return registry;
}

export function lookupClient(
  registry: ClientRegistry,
  clientId: string | undefined,
): ClientEntry | undefined {
  if (!clientId) return undefined;
  return registry[clientId];
}

function normalizeReturnOrigin(raw: string, clientId: string): string {
  return normalizeHttpsOrigin(
    raw,
    `ADMITONE_CONNECT_CLIENTS entry "${clientId}" returnOrigin`,
    { allowLocalhostHttp: true },
  );
}
