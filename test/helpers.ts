import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createApp } from "../src/app.js";
import { issuerAndResource, type Config } from "../src/config.js";

export const ISSUER = "http://localhost:3000";
export const RESOURCE = `${ISSUER}/mcp`;
export const REDIRECT_URI = "http://localhost:6274/oauth/callback";
export const USER = { username: "demo", password: "correct-horse-battery" };

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 3000,
    ...issuerAndResource(ISSUER),
    demoUser: USER,
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600,
    authCodeTtlSeconds: 60,
    rateLimitPerMinute: 1000,
    trustProxy: false,
    ...overrides,
  };
}

/** An app with a controllable clock and a `fetch` that never touches the network. */
export function setup(overrides: Partial<Config> = {}) {
  const clock = { now: Date.parse("2026-10-27T12:00:00Z") };
  const app = createApp({ config: testConfig(overrides), now: () => clock.now });
  const fetch = (input: string | URL | Request, init?: RequestInit) =>
    Promise.resolve(app.fetch(input instanceof Request ? input : new Request(input, init)));
  return { app, clock, fetch, advance: (seconds: number) => (clock.now += seconds * 1000) };
}

export type TestEnv = ReturnType<typeof setup>;

export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export async function register(env: TestEnv, body: Record<string, unknown> = {}) {
  const res = await env.fetch(`${ISSUER}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Test client", redirect_uris: [REDIRECT_URI], ...body }),
  });
  assert.equal(res.status, 201, await res.clone().text());
  return (await res.json()) as { client_id: string };
}

export function authorizeUrl(params: Record<string, string>) {
  const url = new URL(`${ISSUER}/authorize`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url;
}

/** Opens the consent page and returns the hidden request id. */
export async function openConsent(env: TestEnv, url: URL | string) {
  const res = await env.fetch(url);
  assert.equal(res.status, 200, await res.clone().text());
  const requestId = /name="request_id" value="([^"]+)"/.exec(await res.text())?.[1];
  assert.ok(requestId, "consent page must contain a request id");
  return requestId;
}

export async function submitConsent(env: TestEnv, requestId: string, fields: Record<string, string> = {}) {
  return env.fetch(`${ISSUER}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: requestId, decision: "approve", ...USER, ...fields }),
    redirect: "manual",
  });
}

/** Full front-channel leg: register, open the consent page, log in, return the code. */
export async function getCode(env: TestEnv, opts: { scope?: string; state?: string } = {}) {
  const client = await register(env);
  const { verifier, challenge } = pkce();
  const url = authorizeUrl({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: opts.state ?? "xyz",
    resource: RESOURCE,
    ...(opts.scope ? { scope: opts.scope } : {}),
  });
  const res = await submitConsent(env, await openConsent(env, url));
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get("location")!);
  const code = location.searchParams.get("code");
  assert.ok(code, `expected a code in ${location}`);
  return { clientId: client.client_id, code, verifier, location };
}

export async function token(env: TestEnv, params: Record<string, string>) {
  const res = await env.fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

export async function exchange(env: TestEnv, c: { clientId: string; code: string; verifier: string }) {
  return token(env, {
    grant_type: "authorization_code",
    client_id: c.clientId,
    code: c.code,
    code_verifier: c.verifier,
    redirect_uri: REDIRECT_URI,
    resource: RESOURCE,
  });
}

/** Logs in and returns a fresh token pair. */
export async function login(env: TestEnv, scope?: string) {
  const c = await getCode(env, { scope });
  const res = await exchange(env, c);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return { clientId: c.clientId, accessToken: res.body.access_token!, refreshToken: res.body.refresh_token! };
}

let rpcId = 0;
export async function rpc(env: TestEnv, accessToken: string | undefined, method: string, params: unknown = {}) {
  return env.fetch(RESOURCE, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
}
