import type { RequestHandler } from "express";

interface RateLimitOptions {
  windowMs: number;
  limit: number;
  keyPrefix: string;
}

type Counter = { count: number; resetAt: number };

export function rateLimit(options: RateLimitOptions): RequestHandler {
  const counters = new Map<string, Counter>();
  return (req, res, next) => {
    const now = Date.now();
    const key = `${options.keyPrefix}:${req.ip || req.socket.remoteAddress || "unknown"}`;
    const current = counters.get(key);
    const counter = !current || current.resetAt <= now
      ? { count: 0, resetAt: now + options.windowMs }
      : current;
    counter.count += 1;
    counters.set(key, counter);

    res.setHeader("RateLimit-Limit", String(options.limit));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, options.limit - counter.count)));
    res.setHeader("RateLimit-Reset", String(Math.ceil(counter.resetAt / 1000)));

    if (counter.count > options.limit) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((counter.resetAt - now) / 1000))));
      res.status(429).json({ error: "rate_limited", message: "too many requests" });
      return;
    }

    if (counters.size > 10_000) {
      for (const [candidate, value] of counters) {
        if (value.resetAt <= now) counters.delete(candidate);
      }
    }
    next();
  };
}
