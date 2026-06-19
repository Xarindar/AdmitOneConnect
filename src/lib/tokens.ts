import crypto from "node:crypto";

/**
 * Shared token helpers. These MUST stay byte-for-byte compatible with the
 * client side (Showrunner deployments), so do not change the encoding.
 *
 * Token format (JWT-like, HMAC-SHA256):
 *   enc = base64url(utf8(JSON.stringify(payload)))
 *   sig = base64url(HMAC_SHA256(secret, enc))   // HMAC over the ASCII bytes of `enc`
 *   token = enc + "." + sig
 */

export function base64urlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64urlDecode(input: string): Buffer {
  const padLen = (4 - (input.length % 4)) % 4;
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLen);
  return Buffer.from(b64, "base64");
}

function hmac(secret: string, enc: string): Buffer {
  return crypto.createHmac("sha256", secret).update(enc, "ascii").digest();
}

export function sign(payloadObj: unknown, secret: string): string {
  const enc = base64urlEncode(JSON.stringify(payloadObj));
  const sig = base64urlEncode(hmac(secret, enc));
  return `${enc}.${sig}`;
}

export class TokenError extends Error {}

/**
 * Verify a token's signature (timing-safe) and expiry, returning the payload.
 * Throws TokenError on any malformed token, bad signature, or expired payload.
 */
export function verify<T = Record<string, unknown>>(
  token: string,
  secret: string,
): T {
  if (typeof token !== "string" || token.length === 0) {
    throw new TokenError("missing token");
  }
  const parts = token.split(".");
  if (parts.length !== 2) {
    throw new TokenError("malformed token");
  }
  const [enc, sig] = parts;
  if (!enc || !sig) {
    throw new TokenError("malformed token");
  }

  const expected = base64urlEncode(hmac(secret, enc));
  const sigBuf = Buffer.from(sig, "utf8");
  const expectedBuf = Buffer.from(expected, "utf8");
  if (
    sigBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(sigBuf, expectedBuf)
  ) {
    throw new TokenError("bad signature");
  }

  let payload: T;
  try {
    payload = JSON.parse(base64urlDecode(enc).toString("utf8")) as T;
  } catch {
    throw new TokenError("invalid payload");
  }

  const exp = (payload as { exp?: unknown }).exp;
  if (typeof exp === "number" && exp <= Math.floor(Date.now() / 1000)) {
    throw new TokenError("token expired");
  }

  return payload;
}
