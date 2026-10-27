import { z } from "zod";

/** Scopes this server understands. Each MCP tool requires exactly one of them. */
export const SUPPORTED_SCOPES = ["notes:read", "notes:write"] as const;
export type Scope = (typeof SUPPORTED_SCOPES)[number];

export interface Config {
  port: number;
  /** Public origin of this server, e.g. https://mcp.example.com. Also the OAuth `issuer`. */
  issuer: string;
  /** Canonical URI of the protected MCP endpoint (RFC 8707 resource / token audience). */
  resource: string;
  demoUser: { username: string; password: string };
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  authCodeTtlSeconds: number;
  /** Requests per minute per client IP on /register, /token and the login form. */
  rateLimitPerMinute: number;
  /** Read the client IP from X-Forwarded-For. Only enable behind a proxy you control. */
  trustProxy: boolean;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

const envSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  ISSUER_URL: z.url().optional(),
  DEMO_USERNAME: z.string().min(1),
  DEMO_PASSWORD: z.string().min(8, "DEMO_PASSWORD must have at least 8 characters"),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(600),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 30),
  AUTH_CODE_TTL_SECONDS: z.coerce.number().int().positive().max(600).default(60),
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(30),
  TRUST_PROXY: z.enum(["true", "false"]).default("false"),
});

/**
 * Builds the configuration from environment variables. Fails fast with a readable
 * message instead of booting a half-configured authorization server.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid configuration:\n${issues.join("\n")}`);
  }
  const e = parsed.data;
  return {
    port: e.PORT,
    ...issuerAndResource(e.ISSUER_URL ?? `http://localhost:${e.PORT}`),
    demoUser: { username: e.DEMO_USERNAME, password: e.DEMO_PASSWORD },
    accessTokenTtlSeconds: e.ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlSeconds: e.REFRESH_TOKEN_TTL_SECONDS,
    authCodeTtlSeconds: e.AUTH_CODE_TTL_SECONDS,
    rateLimitPerMinute: e.RATE_LIMIT_PER_MINUTE,
    trustProxy: e.TRUST_PROXY === "true",
  };
}

/**
 * OAuth 2.1 requires TLS for every endpoint except loopback during development.
 * The issuer must be a bare origin so the RFC 8414 well-known URL stays at the root.
 */
export function issuerAndResource(issuerUrl: string): { issuer: string; resource: string } {
  const url = new URL(issuerUrl);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) {
    throw new Error("ISSUER_URL must use https (plain http is only allowed for localhost)");
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error("ISSUER_URL must be an origin without path, query or fragment");
  }
  return { issuer: url.origin, resource: `${url.origin}/mcp` };
}
