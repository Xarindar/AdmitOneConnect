import crypto from "node:crypto";
import { base64urlEncode } from "./tokens.js";

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
  const candidates = normalizeSignatureHeader(headerValue);

  return candidates.some((candidate) => timingSafeEqualText(candidate, expected));
}

function normalizeSignatureHeader(headerValue: string): string[] {
  return headerValue
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const equalsIndex = part.indexOf("=");
      return equalsIndex >= 0 ? part.slice(equalsIndex + 1).trim() : part;
    });
}

function timingSafeEqualText(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a, "utf8");
  const bBuffer = Buffer.from(b, "utf8");
  return aBuffer.length === bBuffer.length && crypto.timingSafeEqual(aBuffer, bBuffer);
}
