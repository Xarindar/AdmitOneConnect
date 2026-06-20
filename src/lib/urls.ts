import { URL } from "node:url";

interface HttpsOptions {
  allowLocalhostHttp?: boolean;
}

export function normalizeHttpsBaseUrl(
  raw: string,
  label: string,
  options: HttpsOptions = {},
): string {
  const parsed = parseAbsoluteUrl(raw, `${label} must be a valid absolute URL`);
  requireHttps(parsed, `${label} must be HTTPS outside localhost`, options);

  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/$/, "");
}

export function normalizeHttpsOrigin(
  raw: string,
  label: string,
  options: HttpsOptions = {},
): string {
  const parsed = parseAbsoluteUrl(raw, `${label} must be a valid URL origin`);
  requireHttps(parsed, `${label} must be HTTPS outside localhost`, options);

  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    throw new Error(`${label} must not include a path, query, or hash`);
  }

  return parsed.origin;
}

function parseAbsoluteUrl(raw: string, errorMessage: string): URL {
  try {
    return new URL(raw);
  } catch {
    throw new Error(errorMessage);
  }
}

function requireHttps(parsed: URL, errorMessage: string, options: HttpsOptions): void {
  if (parsed.protocol === "https:") return;
  if (options.allowLocalhostHttp && parsed.protocol === "http:" && parsed.hostname === "localhost") {
    return;
  }
  throw new Error(errorMessage);
}
