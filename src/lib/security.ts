import crypto from "node:crypto";

export function timingSafeEqualText(candidate: string, expected: string): boolean {
  const candidateBuffer = Buffer.from(candidate, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  const comparableCandidate =
    candidateBuffer.length === expectedBuffer.length
      ? candidateBuffer
      : Buffer.alloc(expectedBuffer.length);

  return (
    crypto.timingSafeEqual(comparableCandidate, expectedBuffer) &&
    candidateBuffer.length === expectedBuffer.length
  );
}
