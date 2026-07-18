import crypto from "node:crypto";
import { timingSafeEqualText } from "./security.js";
import { base64urlEncode } from "./tokens.js";

const BASE64URL_SHA256_LENGTH = 43;
const BASE64URL_SHA256_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function signRawBody(rawBody: string, secret: string): string {
  return base64urlEncode(
    crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest(),
  );
}

export function verifyRawBodySignature(
  rawBody: string,
  headerValue: string | undefined,
  secret: string,
): boolean {
  if (!headerValue) return false;

  const expected = signRawBody(rawBody, secret);
  const candidate = normalizeSignatureHeader(headerValue);

  return candidate !== undefined && timingSafeEqualText(candidate, expected);
}

function normalizeSignatureHeader(headerValue: string): string | undefined {
  const value = headerValue.trim();
  if (value.includes(",")) return undefined;

  const candidate = value.startsWith("v1=") ? value.slice("v1=".length).trim() : value;
  if (
    candidate.length !== BASE64URL_SHA256_LENGTH ||
    !BASE64URL_SHA256_PATTERN.test(candidate)
  ) {
    return undefined;
  }

  return candidate;
}
