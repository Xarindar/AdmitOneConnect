import crypto from "node:crypto";
import { isRecord } from "./objects.js";
import { timingSafeEqualText } from "./security.js";

/**
 * Shared token helpers. These formats MUST stay byte-for-byte compatible with
 * the client side (Showrunner deployments), so change them only with a planned
 * client rollout.
 *
 * Signed token format (JWT-like, HMAC-SHA256):
 *   enc = base64url(utf8(JSON.stringify(payload)))
 *   sig = base64url(HMAC_SHA256(secret, enc))   // HMAC over the ASCII bytes of `enc`
 *   token = enc + "." + sig
 *
 * Sealed token format (AES-256-GCM):
 *   v1.base64url(iv).base64url(ciphertext).base64url(tag)
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
  expectedType?: string,
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
  if (!timingSafeEqualText(sig, expected)) {
    throw new TokenError("bad signature");
  }

  let payload: T;
  try {
    payload = JSON.parse(base64urlDecode(enc).toString("utf8")) as T;
  } catch {
    throw new TokenError("invalid payload");
  }

  validateTokenPayload(payload, expectedType);

  return payload;
}

export function seal(payloadObj: unknown, secret: string, expectedType: string): string {
  validateTokenPayload(payloadObj, expectedType);

  const iv = crypto.randomBytes(12);
  const key = deriveAeadKey(secret, expectedType);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(expectedType, "utf8"));

  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payloadObj), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    "v1",
    base64urlEncode(iv),
    base64urlEncode(ciphertext),
    base64urlEncode(tag),
  ].join(".");
}

export function open<T = Record<string, unknown>>(
  token: string,
  secret: string,
  expectedType: string,
): T {
  if (typeof token !== "string" || token.length === 0) {
    throw new TokenError("missing token");
  }

  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new TokenError("malformed token");
  }

  const [, encodedIv, encodedCiphertext, encodedTag] = parts;
  if (!encodedIv || !encodedCiphertext || !encodedTag) {
    throw new TokenError("malformed token");
  }

  let plaintext: string;
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      deriveAeadKey(secret, expectedType),
      base64urlDecode(encodedIv),
    );
    decipher.setAAD(Buffer.from(expectedType, "utf8"));
    decipher.setAuthTag(base64urlDecode(encodedTag));
    plaintext = Buffer.concat([
      decipher.update(base64urlDecode(encodedCiphertext)),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new TokenError("bad token");
  }

  let payload: T;
  try {
    payload = JSON.parse(plaintext) as T;
  } catch {
    throw new TokenError("invalid payload");
  }

  validateTokenPayload(payload, expectedType);
  return payload;
}

function validateTokenPayload(payload: unknown, expectedType: string | undefined): void {
  if (!isRecord(payload)) {
    throw new TokenError("token payload must be an object");
  }

  if (typeof payload.typ !== "string" || payload.typ.trim() === "") {
    throw new TokenError("token missing type");
  }
  if (expectedType && payload.typ !== expectedType) {
    throw new TokenError("token type mismatch");
  }

  const exp = payload.exp;
  if (typeof exp !== "number" || !Number.isInteger(exp)) {
    throw new TokenError("token missing expiry");
  }
  if (exp <= Math.floor(Date.now() / 1000)) {
    throw new TokenError("token expired");
  }
}

function deriveAeadKey(secret: string, tokenType: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(secret, "utf8"),
      Buffer.from("admitone-connect:v1", "utf8"),
      Buffer.from(`token:${tokenType}`, "utf8"),
      32,
    ),
  );
}
