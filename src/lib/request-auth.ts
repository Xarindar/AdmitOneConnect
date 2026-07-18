import crypto from "node:crypto";
import { timingSafeEqualText } from "./security.js";
import { base64urlEncode } from "./tokens.js";

export interface ServiceRequestEnvelope {
  client_id: string;
  site_id: string;
  provider: string;
  iat: number;
  exp: number;
  request_id: string;
}

export function signServiceRequest(
  method: string,
  path: string,
  rawBody: string,
  envelope: ServiceRequestEnvelope,
  secret: string,
): string {
  const canonical = canonicalRequest(method, path, rawBody, envelope);
  const signature = base64urlEncode(
    crypto.createHmac("sha256", secret).update(canonical, "utf8").digest(),
  );
  return `v1=${signature}`;
}

export function verifyServiceRequest(
  method: string,
  path: string,
  rawBody: string,
  envelope: ServiceRequestEnvelope,
  headerValue: string | undefined,
  secret: string,
): boolean {
  if (!headerValue || headerValue.includes(",")) return false;
  const candidate = headerValue.trim();
  const expected = signServiceRequest(method, path, rawBody, envelope, secret);
  return /^v1=[A-Za-z0-9_-]{43}$/.test(candidate) && timingSafeEqualText(candidate, expected);
}

function canonicalRequest(
  method: string,
  path: string,
  rawBody: string,
  envelope: ServiceRequestEnvelope,
): string {
  const bodyDigest = crypto.createHash("sha256").update(rawBody, "utf8").digest("hex");
  return [
    "admitone-service-request-v1",
    method.toUpperCase(),
    path,
    envelope.client_id,
    envelope.site_id,
    envelope.provider,
    String(envelope.iat),
    String(envelope.exp),
    envelope.request_id,
    bodyDigest,
  ].join("\n");
}
