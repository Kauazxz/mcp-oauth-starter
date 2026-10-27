import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  OAuthMetadataSchema,
  OAuthProtectedResourceMetadataSchema,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  ISSUER,
  REDIRECT_URI,
  RESOURCE,
  authorizeUrl,
  exchange,
  getCode,
  login,
  openConsent,
  pkce,
  register,
  rpc,
  setup,
  submitConsent,
  token,
} from "./helpers.js";

describe("discovery", () => {
  it("serves RFC 8414 and RFC 9728 metadata that the MCP SDK accepts", async () => {
    const env = setup();
    const as = OAuthMetadataSchema.parse(await (await env.fetch(`${ISSUER}/.well-known/oauth-authorization-server`)).json());
    assert.equal(as.issuer, ISSUER);
    assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(as.token_endpoint_auth_methods_supported, ["none"]);

    for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const pr = OAuthProtectedResourceMetadataSchema.parse(await (await env.fetch(ISSUER + path)).json());
      assert.equal(pr.resource, RESOURCE);
      assert.deepEqual(pr.authorization_servers, [ISSUER]);
    }
  });
});

describe("dynamic client registration", () => {
  it("registers a public client", async () => {
    const env = setup();
    const res = await env.fetch(`${ISSUER}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: "client_secret_basic" }),
    });
    assert.equal(res.status, 201);
    const body = (await res.json()) as Record<string, unknown>;
    assert.match(String(body.client_id), /^mcp_client_/);
    assert.equal(body.token_endpoint_auth_method, "none");
    assert.equal(body.client_secret, undefined);
  });

  it("rejects non-loopback http and fragment redirect URIs", async () => {
    const env = setup();
    for (const uri of ["http://evil.example/cb", "https://app.example/cb#frag", "javascript:alert(1)"]) {
      const res = await env.fetch(`${ISSUER}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: [uri] }),
      });
      assert.equal(res.status, 400, uri);
      assert.equal(((await res.json()) as { error: string }).error, "invalid_redirect_uri");
    }
  });

  it("is rate limited", async () => {
    const env = setup({ rateLimitPerMinute: 2 });
    const send = () =>
      env.fetch(`${ISSUER}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: [REDIRECT_URI] }),
      });
    assert.equal((await send()).status, 201);
    assert.equal((await send()).status, 201);
    const limited = await send();
    assert.equal(limited.status, 429);
    assert.ok(limited.headers.get("retry-after"));
    env.advance(61);
    assert.equal((await send()).status, 201);
  });
});

describe("authorization endpoint", () => {
  async function baseParams(env: ReturnType<typeof setup>) {
    const { client_id } = await register(env);
    return {
      response_type: "code",
      client_id,
      redirect_uri: REDIRECT_URI,
      code_challenge: pkce().challenge,
      code_challenge_method: "S256",
      state: "s-123",
    };
  }

  it("does not redirect to an unregistered redirect_uri", async () => {
    const env = setup();
    const params = await baseParams(env);
    const res = await env.fetch(authorizeUrl({ ...params, redirect_uri: "http://localhost:6274/other" }));
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("location"), null);
    assert.match(await res.text(), /redirect_uri/);
  });

  it("rejects the plain PKCE method and missing challenges with a redirect error", async () => {
    const env = setup();
    const params = await baseParams(env);
    const cases = [{ code_challenge_method: "plain" }, { code_challenge: "" }, { code_challenge_method: "" }];
    for (const override of cases) {
      const res = await env.fetch(authorizeUrl({ ...params, ...override }), { redirect: "manual" });
      assert.equal(res.status, 302, JSON.stringify(override));
      const location = new URL(res.headers.get("location")!);
      assert.equal(location.searchParams.get("error"), "invalid_request");
      assert.equal(location.searchParams.get("state"), "s-123");
    }
  });

  it("rejects unknown scopes and foreign resources", async () => {
    const env = setup();
    const params = await baseParams(env);
    const scopeRes = await env.fetch(authorizeUrl({ ...params, scope: "admin" }), { redirect: "manual" });
    assert.equal(new URL(scopeRes.headers.get("location")!).searchParams.get("error"), "invalid_scope");
    const resRes = await env.fetch(authorizeUrl({ ...params, resource: "https://other.example/mcp" }), {
      redirect: "manual",
    });
    assert.equal(new URL(resRes.headers.get("location")!).searchParams.get("error"), "invalid_target");
  });

  it("re-prompts on a wrong password and redirects with access_denied on deny", async () => {
    const env = setup();
    const params = await baseParams(env);
    const requestId = await openConsent(env, authorizeUrl(params));
    const wrong = await submitConsent(env, requestId, { password: "nope" });
    assert.equal(wrong.status, 401);
    assert.match(await wrong.text(), /Invalid username or password/);

    const denied = await submitConsent(env, requestId, { decision: "deny" });
    const location = new URL(denied.headers.get("location")!);
    assert.equal(location.searchParams.get("error"), "access_denied");
    assert.equal(location.searchParams.get("state"), "s-123");
    // The pending request is gone after a decision.
    assert.equal((await submitConsent(env, requestId)).status, 400);
  });

  it("returns code, state and iss on approval and protects the page from framing", async () => {
    const env = setup();
    const params = await baseParams(env);
    const page = await env.fetch(authorizeUrl(params));
    assert.equal(page.headers.get("x-frame-options"), "DENY");
    assert.match(page.headers.get("content-security-policy")!, /frame-ancestors 'none'/);

    const { location } = await getCode(env, { state: "opaque-state" });
    assert.equal(location.origin + location.pathname, REDIRECT_URI);
    assert.equal(location.searchParams.get("state"), "opaque-state");
    assert.equal(location.searchParams.get("iss"), ISSUER);
  });
});

describe("token endpoint: authorization_code", () => {
  it("exchanges a code with the right PKCE verifier", async () => {
    const env = setup();
    const res = await exchange(env, await getCode(env));
    assert.equal(res.status, 200);
    assert.match(res.body.access_token!, /^mcp_at_/);
    assert.match(res.body.refresh_token!, /^mcp_rt_/);
    assert.equal(res.body.token_type, "Bearer");
    assert.equal(res.body.scope, "notes:read notes:write");
  });

  it("rejects a wrong PKCE verifier", async () => {
    const env = setup();
    const c = await getCode(env);
    const res = await exchange(env, { ...c, verifier: pkce().verifier });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, "invalid_grant");
    assert.match(res.body.error_description!, /PKCE/);
  });

  it("rejects a redirect_uri that differs from the authorization request", async () => {
    const env = setup();
    const c = await getCode(env);
    const res = await token(env, {
      grant_type: "authorization_code",
      client_id: c.clientId,
      code: c.code,
      code_verifier: c.verifier,
      redirect_uri: "http://localhost:6274/oauth/other",
    });
    assert.equal(res.body.error, "invalid_grant");
  });

  it("rejects a code presented by another client", async () => {
    const env = setup();
    const c = await getCode(env);
    const other = await register(env);
    const res = await exchange(env, { ...c, clientId: other.client_id });
    assert.equal(res.body.error, "invalid_grant");
  });

  it("rejects code reuse and revokes the tokens issued from it", async () => {
    const env = setup();
    const c = await getCode(env);
    const first = await exchange(env, c);
    assert.equal(first.status, 200);
    assert.equal((await rpc(env, first.body.access_token, "tools/list")).status, 200);

    const second = await exchange(env, c);
    assert.equal(second.body.error, "invalid_grant");
    assert.equal((await rpc(env, first.body.access_token, "tools/list")).status, 401);
    const refreshed = await token(env, {
      grant_type: "refresh_token",
      client_id: c.clientId,
      refresh_token: first.body.refresh_token!,
    });
    assert.equal(refreshed.body.error, "invalid_grant");
  });

  it("rejects an expired code", async () => {
    const env = setup();
    const c = await getCode(env);
    env.advance(61);
    const res = await exchange(env, c);
    assert.equal(res.body.error, "invalid_grant");
    assert.match(res.body.error_description!, /expired/);
  });

  it("rejects unknown clients, grant types and duplicated parameters", async () => {
    const env = setup();
    assert.equal((await token(env, { grant_type: "authorization_code", client_id: "nope" })).status, 401);
    const { client_id } = await register(env);
    assert.equal((await token(env, { grant_type: "password", client_id })).body.error, "unsupported_grant_type");

    const dup = await env.fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=authorization_code&client_id=${client_id}&code=a&code=b&code_verifier=x`,
    });
    assert.equal(((await dup.json()) as { error: string }).error, "invalid_request");
  });
});

describe("token endpoint: refresh_token", () => {
  it("rotates refresh tokens and detects reuse by revoking the whole family", async () => {
    const env = setup();
    const t0 = await login(env);
    const refresh = (refreshToken: string) =>
      token(env, { grant_type: "refresh_token", client_id: t0.clientId, refresh_token: refreshToken });

    const t1 = await refresh(t0.refreshToken);
    assert.equal(t1.status, 200);
    assert.notEqual(t1.body.refresh_token, t0.refreshToken);
    const t2 = await refresh(t1.body.refresh_token!);
    assert.equal(t2.status, 200);
    assert.equal((await rpc(env, t2.body.access_token, "tools/list")).status, 200);

    // An attacker replays the first, already rotated, refresh token.
    const replay = await refresh(t0.refreshToken);
    assert.equal(replay.body.error, "invalid_grant");
    assert.match(replay.body.error_description!, /reuse/);

    // Every token of the family is now dead, including the legitimate latest pair.
    assert.equal((await refresh(t2.body.refresh_token!)).body.error, "invalid_grant");
    assert.equal((await rpc(env, t2.body.access_token, "tools/list")).status, 401);
    assert.equal((await rpc(env, t0.accessToken, "tools/list")).status, 401);

    // Other grants are untouched.
    const unrelated = await login(env);
    assert.equal((await rpc(env, unrelated.accessToken, "tools/list")).status, 200);
  });

  it("allows down-scoping but not up-scoping", async () => {
    const env = setup();
    const t = await login(env, "notes:read");
    const up = await token(env, {
      grant_type: "refresh_token",
      client_id: t.clientId,
      refresh_token: t.refreshToken,
      scope: "notes:read notes:write",
    });
    assert.equal(up.body.error, "invalid_scope");

    const full = await login(env);
    const down = await token(env, {
      grant_type: "refresh_token",
      client_id: full.clientId,
      refresh_token: full.refreshToken,
      scope: "notes:read",
    });
    assert.equal(down.status, 200);
    assert.equal(down.body.scope, "notes:read");
  });

  it("rejects a refresh token from another client", async () => {
    const env = setup();
    const t = await login(env);
    const other = await register(env);
    const res = await token(env, { grant_type: "refresh_token", client_id: other.client_id, refresh_token: t.refreshToken });
    assert.equal(res.body.error, "invalid_grant");
  });
});
