import type { Context, MiddlewareHandler } from "hono";

/**
 * Fixed-window, in-memory rate limiter keyed by client IP and route. Enough to slow down
 * brute force and registration spam on a single instance; use a shared store (Redis,
 * the database) when running more than one replica.
 */
export function rateLimit(opts: {
  limit: number;
  windowMs?: number;
  trustProxy: boolean;
  now?: () => number;
}): MiddlewareHandler {
  const windowMs = opts.windowMs ?? 60_000;
  const now = opts.now ?? Date.now;
  const hits = new Map<string, { count: number; resetAt: number }>();

  return async (c, next) => {
    const t = now();
    if (hits.size > 10_000) {
      for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
    }
    const key = `${clientIp(c, opts.trustProxy)} ${c.req.method} ${c.req.path}`;
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= t) {
      entry = { count: 0, resetAt: t + windowMs };
      hits.set(key, entry);
    }
    entry.count++;
    if (entry.count > opts.limit) {
      c.header("Retry-After", String(Math.ceil((entry.resetAt - t) / 1000)));
      return c.json({ error: "too_many_requests", error_description: "Rate limit exceeded" }, 429);
    }
    await next();
  };
}

function clientIp(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = c.req.header("x-forwarded-for")?.split(",")[0]?.trim();
    if (forwarded) return forwarded;
  }
  // @hono/node-server exposes the Node request as `c.env.incoming`.
  const env = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  return env?.incoming?.socket?.remoteAddress ?? "unknown";
}
