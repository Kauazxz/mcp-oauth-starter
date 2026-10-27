import { Hono, type Context } from "hono";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { z } from "zod";
import { SUPPORTED_SCOPES, type Config } from "./config.js";
import { isValidPkceValue, randomToken, safeEqual, sha256, verifyPkce } from "./crypto.js";
import { rateLimit } from "./rateLimit.js";
import type { Client, OAuthStore } from "./store.js";
import { consentPage, errorPage } from "./views.js";

export interface Deps {
  config: Config;
  store: OAuthStore;
  now: () => number;
}

const PENDING_TTL_MS = 10 * 60_000;
const MAX_FAILED_LOGINS = 5;

/** An RFC 6749 §5.2 error. `status` is the HTTP status used when it is returned as JSON. */
export class OAuthError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status: 400 | 401 = 400,
  ) {
    super(description);
  }
}

export function authorizationServerMetadata({ issuer }: Config) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    scopes_supported: [...SUPPORTED_SCOPES],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
  };
}

export function protectedResourceMetadata({ issuer, resource }: Config) {
  return {
    resource,
    authorization_servers: [issuer],
    scopes_supported: [...SUPPORTED_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "MCP OAuth Starter (notes demo)",
  };
}

/** RFC 9728 §3.1: the metadata URL for `https://host/mcp` is `/.well-known/oauth-protected-resource/mcp`. */
export function protectedResourceMetadataUrl({ issuer, resource }: Config): string {
  return `${issuer}/.well-known/oauth-protected-resource${new URL(resource).pathname}`;
}

/** Resolves a bearer token to the SDK's AuthInfo, or undefined when it is unknown, expired, revoked or for another audience. */
export async function verifyAccessToken({ config, store, now }: Deps, token: string): Promise<AuthInfo | undefined> {
  const record = await store.getAccessToken(sha256(token));
  if (!record || record.expiresAt <= now() || record.resource !== config.resource) return undefined;
  if (await store.isFamilyRevoked(record.familyId)) return undefined;
  return {
    token,
    clientId: record.clientId,
    scopes: record.scopes,
    expiresAt: Math.floor(record.expiresAt / 1000),
    resource: new URL(record.resource),
    extra: { userId: record.userId },
  };
}

export function oauthRoutes(deps: Deps): Hono {
  const { config, store, now } = deps;
  const app = new Hono();
  const limiter = rateLimit({ limit: config.rateLimitPerMinute, trustProxy: config.trustProxy, now });

  app.get("/.well-known/oauth-authorization-server", (c) => c.json(authorizationServerMetadata(config)));
  for (const path of ["/.well-known/oauth-protected-resource", new URL(protectedResourceMetadataUrl(config)).pathname]) {
    app.get(path, (c) => c.json(protectedResourceMetadata(config)));
  }

  // RFC 7591 dynamic client registration. Only public clients (no secret) are issued.
  app.post("/register", limiter, async (c) => {
    const parsed = registrationSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) {
      return c.json({ error: "invalid_client_metadata", error_description: z.prettifyError(parsed.error) }, 400);
    }
    const meta = parsed.data;
    const badUri = meta.redirect_uris.find((uri) => !isAllowedRedirectUri(uri));
    if (badUri) {
      return c.json(
        { error: "invalid_redirect_uri", error_description: `Use https or an http loopback address: ${badUri}` },
        400,
      );
    }
    const unsupported =
      meta.grant_types?.find((g) => g !== "authorization_code" && g !== "refresh_token") ??
      meta.response_types?.find((r) => r !== "code");
    if (unsupported) {
      return c.json({ error: "invalid_client_metadata", error_description: `Unsupported value: ${unsupported}` }, 400);
    }
    try {
      if (meta.scope) parseScopes(meta.scope, [...SUPPORTED_SCOPES]);
    } catch (err) {
      return c.json({ error: "invalid_client_metadata", error_description: (err as Error).message }, 400);
    }
    const client: Client = {
      clientId: randomToken("mcp_client_"),
      clientName: meta.client_name,
      redirectUris: meta.redirect_uris,
      scope: meta.scope,
      createdAt: now(),
    };
    await store.saveClient(client);
    c.header("Cache-Control", "no-store");
    return c.json(
      {
        client_id: client.clientId,
        client_id_issued_at: Math.floor(client.createdAt / 1000),
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
        scope: client.scope,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        // RFC 7591 §3.2.1 lets the server replace requested values; clients must use what is returned.
        token_endpoint_auth_method: "none",
      },
      201,
    );
  });

  app.get("/authorize", async (c) => {
    const params = new URL(c.req.url).searchParams;
    let client: Client | undefined;
    let redirectUri: string | undefined;
    try {
      const clientId = param(params, "client_id");
      redirectUri = param(params, "redirect_uri");
      client = clientId ? await store.getClient(clientId) : undefined;
    } catch (err) {
      if (err instanceof OAuthError) return html(c, errorPage(err.description), 400);
      throw err;
    }
    // Until client and redirect_uri are verified, errors must NOT redirect (RFC 6749 §4.1.2.1),
    // otherwise the endpoint becomes an open redirector.
    if (!client) return html(c, errorPage("Unknown client_id. Register the client first."), 400);
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return html(c, errorPage("redirect_uri is missing or does not exactly match a registered URI."), 400);
    }
    const state = params.get("state") ?? undefined;
    try {
      if (param(params, "response_type") !== "code") {
        throw new OAuthError("unsupported_response_type", "Only response_type=code is supported");
      }
      const codeChallenge = param(params, "code_challenge");
      if (!codeChallenge || !isValidPkceValue(codeChallenge)) {
        throw new OAuthError("invalid_request", "PKCE is required: send a valid code_challenge");
      }
      if (param(params, "code_challenge_method") !== "S256") {
        throw new OAuthError("invalid_request", "code_challenge_method must be S256");
      }
      const allowed = client.scope ? client.scope.split(" ") : [...SUPPORTED_SCOPES];
      const scopes = parseScopes(param(params, "scope"), allowed);
      const resource = checkResource(param(params, "resource"), config.resource);

      const requestId = randomToken();
      await store.savePending(requestId, {
        clientId: client.clientId,
        redirectUri,
        codeChallenge,
        scopes,
        resource,
        state,
        failedLogins: 0,
        expiresAt: now() + PENDING_TTL_MS,
      });
      const page = consentPage({ requestId, clientName: displayName(client), redirectUri, scopes });
      return html(c, page, 200, redirectUri);
    } catch (err) {
      if (err instanceof OAuthError) {
        return redirectTo(c, config, redirectUri, { error: err.error, error_description: err.description, state });
      }
      throw err;
    }
  });

  app.post("/authorize", limiter, async (c) => {
    let form: URLSearchParams;
    try {
      form = await formBody(c);
    } catch {
      return html(c, errorPage("Malformed form submission."), 400);
    }
    const requestId = form.get("request_id") ?? "";
    const pending = requestId ? await store.getPending(requestId) : undefined;
    const client = pending ? await store.getClient(pending.clientId) : undefined;
    if (!pending || !client) return html(c, errorPage("This authorization request expired or is invalid."), 400);
    const { redirectUri, state } = pending;

    if (form.get("decision") !== "approve") {
      await store.deletePending(requestId);
      return redirectTo(c, config, redirectUri, { error: "access_denied", error_description: "The user denied access", state });
    }

    const username = form.get("username") ?? "";
    const password = form.get("password") ?? "";
    // Both comparisons always run so timing does not reveal which field was wrong.
    const userOk = safeEqual(username, config.demoUser.username);
    const passOk = safeEqual(password, config.demoUser.password);
    if (!userOk || !passOk) {
      pending.failedLogins++;
      if (pending.failedLogins >= MAX_FAILED_LOGINS) {
        await store.deletePending(requestId);
        return redirectTo(c, config, redirectUri, { error: "access_denied", error_description: "Too many failed logins", state });
      }
      await store.savePending(requestId, pending);
      const page = consentPage({
        requestId,
        clientName: displayName(client),
        redirectUri,
        scopes: pending.scopes,
        error: "Invalid username or password.",
      });
      return html(c, page, 401, redirectUri);
    }

    await store.deletePending(requestId);
    const code = randomToken();
    await store.saveCode(sha256(code), {
      clientId: pending.clientId,
      userId: config.demoUser.username,
      redirectUri,
      codeChallenge: pending.codeChallenge,
      scopes: pending.scopes,
      resource: pending.resource,
      familyId: randomToken(),
      expiresAt: now() + config.authCodeTtlSeconds * 1000,
    });
    return redirectTo(c, config, redirectUri, { code, state });
  });

  app.post("/token", limiter, async (c) => {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    try {
      const form = await formBody(c);
      const clientId = param(form, "client_id");
      const client = clientId ? await store.getClient(clientId) : undefined;
      if (!client) throw new OAuthError("invalid_client", "Unknown or missing client_id", 401);

      const grantType = param(form, "grant_type");
      if (grantType === "authorization_code") return c.json(await exchangeCode(deps, form, client));
      if (grantType === "refresh_token") return c.json(await refresh(deps, form, client));
      throw new OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token");
    } catch (err) {
      if (err instanceof OAuthError) {
        return c.json({ error: err.error, error_description: err.description }, err.status);
      }
      throw err;
    }
  });

  return app;
}

async function exchangeCode({ config, store, now }: Deps, form: URLSearchParams, client: Client) {
  const code = param(form, "code");
  const verifier = param(form, "code_verifier");
  if (!code || !verifier) throw new OAuthError("invalid_request", "code and code_verifier are required");

  const hash = sha256(code);
  const record = await store.getCode(hash);
  if (!record || record.clientId !== client.clientId) throw new OAuthError("invalid_grant", "Invalid authorization code");
  if (!(await store.markUsed("code", hash, now()))) {
    // OAuth 2.1 §4.1.3: a replayed code means it leaked; revoke what the first exchange issued.
    await store.revokeFamily(record.familyId, now() + config.refreshTokenTtlSeconds * 1000);
    throw new OAuthError("invalid_grant", "Authorization code was already used");
  }
  // From here on the code is burned, even if a check below fails.
  if (record.expiresAt <= now()) throw new OAuthError("invalid_grant", "Authorization code expired");
  if (param(form, "redirect_uri") !== record.redirectUri) {
    throw new OAuthError("invalid_grant", "redirect_uri does not match the authorization request");
  }
  if (!verifyPkce(verifier, record.codeChallenge)) throw new OAuthError("invalid_grant", "PKCE verification failed");
  checkResource(param(form, "resource"), record.resource);
  return issueTokens({ config, store, now }, record, record.scopes);
}

async function refresh({ config, store, now }: Deps, form: URLSearchParams, client: Client) {
  const token = param(form, "refresh_token");
  if (!token) throw new OAuthError("invalid_request", "refresh_token is required");

  const hash = sha256(token);
  const record = await store.getRefreshToken(hash);
  if (!record || record.clientId !== client.clientId) throw new OAuthError("invalid_grant", "Invalid refresh token");
  if (await store.isFamilyRevoked(record.familyId)) throw new OAuthError("invalid_grant", "Refresh token was revoked");
  // Validate the request before consuming the token, so a malformed request does not burn it.
  const scopes = parseScopes(param(form, "scope"), record.scopes);
  checkResource(param(form, "resource"), record.resource);
  if (!(await store.markUsed("refresh", hash, now()))) {
    // Rotation means each refresh token works once. A second use means two parties hold it,
    // and we cannot tell which one is legitimate, so the whole grant is revoked.
    await store.revokeFamily(record.familyId, now() + config.refreshTokenTtlSeconds * 1000);
    throw new OAuthError("invalid_grant", "Refresh token reuse detected; the grant was revoked");
  }
  if (record.expiresAt <= now()) throw new OAuthError("invalid_grant", "Refresh token expired");
  return issueTokens({ config, store, now }, record, scopes);
}

/** Issues a new access token (possibly down-scoped) and a rotated refresh token for the same grant. */
async function issueTokens(
  { config, store, now }: Deps,
  grant: { clientId: string; userId: string; scopes: string[]; resource: string; familyId: string },
  accessScopes: string[],
) {
  const base = { clientId: grant.clientId, userId: grant.userId, resource: grant.resource, familyId: grant.familyId };
  const accessToken = randomToken("mcp_at_");
  const refreshToken = randomToken("mcp_rt_");
  await store.saveAccessToken(sha256(accessToken), {
    ...base,
    scopes: accessScopes,
    expiresAt: now() + config.accessTokenTtlSeconds * 1000,
  });
  await store.saveRefreshToken(sha256(refreshToken), {
    ...base,
    scopes: grant.scopes,
    expiresAt: now() + config.refreshTokenTtlSeconds * 1000,
  });
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: config.accessTokenTtlSeconds,
    refresh_token: refreshToken,
    scope: accessScopes.join(" "),
  };
}

const registrationSchema = z.object({
  redirect_uris: z.array(z.string().max(2000)).min(1).max(10),
  client_name: z.string().max(200).optional(),
  scope: z.string().max(500).optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  token_endpoint_auth_method: z.string().optional(),
});

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** https anywhere, plain http only on loopback (RFC 8252 §7.3). No fragments (RFC 6749 §3.1.2). */
function isAllowedRedirectUri(uri: string): boolean {
  if (!URL.canParse(uri)) return false;
  const url = new URL(uri);
  if (url.hash || url.username || url.password) return false;
  return url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname));
}

/** Reads a parameter that must appear at most once (RFC 6749 §3.1 / §3.2). */
function param(params: URLSearchParams, key: string): string | undefined {
  const values = params.getAll(key);
  if (values.length > 1) throw new OAuthError("invalid_request", `Parameter "${key}" was sent more than once`);
  return values[0] || undefined;
}

/** Parses a space-delimited scope string; every scope must be in `allowed`. */
function parseScopes(raw: string | undefined, allowed: string[]): string[] {
  const requested = [...new Set((raw ?? "").split(" ").filter(Boolean))];
  if (requested.length === 0) return allowed;
  const bad = requested.find((s) => !allowed.includes(s));
  if (bad) throw new OAuthError("invalid_scope", `Scope "${bad}" is not allowed`);
  return requested;
}

/** RFC 8707: tokens are bound to one audience. Missing `resource` defaults to this server's MCP endpoint. */
function checkResource(raw: string | undefined, expected: string): string {
  if (raw === undefined) return expected;
  if (raw.replace(/\/$/, "") !== expected) {
    throw new OAuthError("invalid_target", `Unknown resource; this server only issues tokens for ${expected}`);
  }
  return expected;
}

async function formBody(c: Context): Promise<URLSearchParams> {
  if (!c.req.header("content-type")?.startsWith("application/x-www-form-urlencoded")) {
    throw new OAuthError("invalid_request", "Body must be application/x-www-form-urlencoded");
  }
  return new URLSearchParams(await c.req.text());
}

function displayName(client: Client): string {
  return client.clientName || new URL(client.redirectUris[0] ?? "https://unknown").host;
}

function html(c: Context, body: string, status: 200 | 400 | 401, redirectUri?: string) {
  c.header("Cache-Control", "no-store");
  c.header("X-Frame-Options", "DENY");
  // form-action also governs the redirect that follows the POST, so the client's origin is allowed.
  const formAction = redirectUri ? `'self' ${new URL(redirectUri).origin}` : "'self'";
  c.header(
    "Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
  );
  return c.html(body, status);
}

function redirectTo(c: Context, config: Config, redirectUri: string, values: Record<string, string | undefined>) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(values)) if (value !== undefined) url.searchParams.set(key, value);
  url.searchParams.set("iss", config.issuer); // RFC 9207 mix-up protection
  c.header("Cache-Control", "no-store");
  return c.redirect(url.toString(), 302);
}
