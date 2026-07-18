import type { RequestHandler } from "express";
import type { ArtifactStore } from "./artifact-store.js";

interface RateLimitOptions {
  windowMs: number;
  limit: number;
  keyPrefix: string;
}

export function rateLimit(store: ArtifactStore, options: RateLimitOptions): RequestHandler {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${options.keyPrefix}:${req.ip || req.socket.remoteAddress || "unknown"}`;
    void store.hitRateLimit(key, options.windowMs).then((counter) => {
      res.setHeader("RateLimit-Limit", String(options.limit));
      res.setHeader("RateLimit-Remaining", String(Math.max(0, options.limit - counter.count)));
      res.setHeader("RateLimit-Reset", String(Math.ceil(counter.resetAt / 1000)));

      if (counter.count > options.limit) {
        res.setHeader("Retry-After", String(Math.max(1, Math.ceil((counter.resetAt - now) / 1000))));
        res.status(429).json({ error: "rate_limited", message: "too many requests" });
        return;
      }
      next();
    }).catch(next);
  };
}
