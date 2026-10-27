import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  discoverOAuthServerInfo,
  exchangeAuthorization,
  extractWWWAuthenticateParams,
  registerClient,
  startAuthorization,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { ISSUER, REDIRECT_URI, RESOURCE, login, openConsent, rpc, setup, submitConsent, type TestEnv } from "./helpers.js";

async function connect(env: TestEnv, accessToken: string) {
  const client = new Client({ name: "test-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
    fetch: env.fetch,
    requestInit: { headers: { authorization: `Bearer ${accessToken}` } },
  });
  await client.connect(transport);
  return client;
}

function text(result: Awaited<ReturnType<Client["callTool"]>>): string {
  const [first] = result.content as { type: string; text: string }[];
  return first!.text;
}

describe("/mcp authentication", () => {
  it("returns 401 with a WWW-Authenticate challenge when the token is missing", async () => {
    const env = setup();
    const res = await rpc(env, undefined, "tools/list");
    assert.equal(res.status, 401);
    const header = res.headers.get("www-authenticate")!;
    assert.match(header, /^Bearer /);
    const { resourceMetadataUrl, scope } = extractWWWAuthenticateParams(res);
    assert.equal(resourceMetadataUrl?.href, `${ISSUER}/.well-known/oauth-protected-resource/mcp`);
    assert.equal(scope, "notes:read notes:write");
  });

  it("returns 401 invalid_token for unknown and expired tokens", async () => {
    const env = setup();
    const unknown = await rpc(env, "mcp_at_not-a-real-token", "tools/list");
    assert.equal(unknown.status, 401);
    assert.equal(extractWWWAuthenticateParams(unknown).error, "invalid_token");

    const { accessToken } = await login(env);
    assert.equal((await rpc(env, accessToken, "tools/list")).status, 200);
    env.advance(601);
    assert.equal((await rpc(env, accessToken, "tools/list")).status, 401);
  });
});

describe("/mcp tools", () => {
  it("creates, lists and searches notes through the official MCP client", async () => {
    const env = setup();
    const { accessToken } = await login(env);
    const client = await connect(env, accessToken);

    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ["create_note", "list_notes", "search_notes"]);

    await client.callTool({ name: "create_note", arguments: { title: "Groceries", body: "Milk and coffee" } });
    await client.callTool({ name: "create_note", arguments: { title: "Ideas", body: "Ship the OAuth starter" } });

    const all = JSON.parse(text(await client.callTool({ name: "list_notes", arguments: {} })));
    assert.equal(all.length, 2);
    const found = JSON.parse(text(await client.callTool({ name: "search_notes", arguments: { query: "COFFEE" } })));
    assert.deepEqual(
      found.map((n: { title: string }) => n.title),
      ["Groceries"],
    );
    await client.close();
  });

  it("answers 403 insufficient_scope when the token lacks the tool's scope", async () => {
    const env = setup();
    const { accessToken } = await login(env, "notes:read");

    const read = await rpc(env, accessToken, "tools/call", { name: "list_notes", arguments: {} });
    assert.equal(read.status, 200);
    const body = (await read.json()) as { result: { isError?: boolean } };
    assert.equal(body.result.isError, undefined);

    const write = await rpc(env, accessToken, "tools/call", {
      name: "create_note",
      arguments: { title: "x", body: "y" },
    });
    assert.equal(write.status, 403);
    const challenge = extractWWWAuthenticateParams(write);
    assert.equal(challenge.error, "insufficient_scope");
    assert.equal(challenge.scope, "notes:write");
  });

  it("rejects GET and DELETE in stateless mode", async () => {
    const env = setup();
    const { accessToken } = await login(env);
    const res = await env.fetch(RESOURCE, { method: "GET", headers: { authorization: `Bearer ${accessToken}` } });
    assert.equal(res.status, 405);
  });
});

describe("interoperability with the MCP SDK OAuth client", () => {
  it("discovers, registers, authorizes and calls a tool using only SDK client helpers", async () => {
    const env = setup();
    const fetchFn = env.fetch;

    const info = await discoverOAuthServerInfo(RESOURCE, { fetchFn });
    assert.equal(info.authorizationServerUrl, ISSUER);
    const metadata = info.authorizationServerMetadata!;

    const clientInformation = await registerClient(ISSUER, {
      metadata,
      clientMetadata: { client_name: "SDK client", redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: "none" },
      fetchFn,
    });
    const { authorizationUrl, codeVerifier } = await startAuthorization(ISSUER, {
      metadata,
      clientInformation,
      redirectUrl: REDIRECT_URI,
      scope: "notes:read notes:write",
      state: "sdk-state",
      resource: new URL(RESOURCE),
    });

    // Play the user: open the consent page and approve.
    const approved = await submitConsent(env, await openConsent(env, authorizationUrl));
    const callback = new URL(approved.headers.get("location")!);
    assert.equal(callback.searchParams.get("state"), "sdk-state");

    const tokens = await exchangeAuthorization(ISSUER, {
      metadata,
      clientInformation,
      authorizationCode: callback.searchParams.get("code")!,
      codeVerifier,
      redirectUri: REDIRECT_URI,
      resource: new URL(RESOURCE),
      fetchFn,
    });
    assert.ok(tokens.refresh_token);

    const client = await connect(env, tokens.access_token);
    const result = await client.callTool({ name: "create_note", arguments: { title: "From the SDK", body: "ok" } });
    assert.equal(JSON.parse(text(result)).title, "From the SDK");
    await client.close();
  });
});
