import { Hono, type Context } from "hono";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { z } from "zod";
import { SUPPORTED_SCOPES, type Config, type Scope } from "./config.js";
import type { NotesStore } from "./notes.js";
import { protectedResourceMetadataUrl, verifyAccessToken, type Deps } from "./oauth.js";

/** Single source of truth for authorization: which scope each tool needs. */
export const TOOL_SCOPES: Record<string, Scope> = {
  create_note: "notes:write",
  list_notes: "notes:read",
  search_notes: "notes:read",
};

type Env = { Variables: { auth: AuthInfo } };

export function createMcpServer(notes: NotesStore): McpServer {
  const server = new McpServer({ name: "mcp-oauth-starter", version: "0.1.0" });

  server.registerTool(
    "create_note",
    {
      title: "Create note",
      description: "Save a new note for the signed-in user.",
      inputSchema: { title: z.string().min(1).max(200), body: z.string().max(10_000) },
      annotations: { readOnlyHint: false, destructiveHint: false },
    },
    async ({ title, body }, { authInfo }) => {
      const note = await notes.create(userFor(authInfo, "create_note"), title, body);
      return json(note);
    },
  );

  server.registerTool(
    "list_notes",
    {
      title: "List notes",
      description: "List every note of the signed-in user, oldest first.",
      annotations: { readOnlyHint: true },
    },
    async ({ authInfo }) => json(await notes.list(userFor(authInfo, "list_notes"))),
  );

  server.registerTool(
    "search_notes",
    {
      title: "Search notes",
      description: "Case-insensitive search in the title and body of the signed-in user's notes.",
      inputSchema: { query: z.string().min(1).max(200) },
      annotations: { readOnlyHint: true },
    },
    async ({ query }, { authInfo }) => json(await notes.search(userFor(authInfo, "search_notes"), query)),
  );

  return server;
}

/**
 * Defense in depth: the HTTP layer already rejects calls without the scope, but the tool
 * checks again so it stays safe if this server is mounted behind a different transport.
 */
function userFor(auth: AuthInfo | undefined, tool: string): string {
  const scope = TOOL_SCOPES[tool];
  const userId = auth?.extra?.userId;
  if (!scope || !auth?.scopes.includes(scope) || typeof userId !== "string") {
    throw new Error(`insufficient_scope: ${tool} requires ${scope}`);
  }
  return userId;
}

function json(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

export function mcpRoutes(deps: Deps, notes: NotesStore): Hono<Env> {
  const app = new Hono<Env>();
  const metadataUrl = protectedResourceMetadataUrl(deps.config);

  // RFC 6750 bearer authentication for every method on /mcp.
  app.use("/mcp", async (c, next) => {
    const token = /^Bearer\s+(\S+)\s*$/i.exec(c.req.header("authorization") ?? "")?.[1];
    if (!token) {
      const scope = SUPPORTED_SCOPES.join(" ");
      return challenge(c, deps.config, 401, `resource_metadata="${metadataUrl}", scope="${scope}"`);
    }
    const auth = await verifyAccessToken(deps, token);
    if (!auth) {
      return challenge(
        c,
        deps.config,
        401,
        `error="invalid_token", error_description="The access token is invalid or expired", resource_metadata="${metadataUrl}"`,
      );
    }
    c.set("auth", auth);
    await next();
  });

  app.post("/mcp", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }, 400);
    }
    const auth = c.get("auth");
    const missing = missingScope(body, auth.scopes);
    if (missing) {
      // MCP step-up authorization: tell the client which scope to request.
      return challenge(
        c,
        deps.config,
        403,
        `error="insufficient_scope", scope="${missing}", resource_metadata="${metadataUrl}"`,
      );
    }

    // Stateless mode: a fresh server and transport per request, so nothing leaks between users.
    const server = createMcpServer(notes);
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    try {
      return await transport.handleRequest(c.req.raw, { authInfo: auth, parsedBody: body });
    } finally {
      await transport.close();
      await server.close();
    }
  });

  // No server-initiated SSE stream and no sessions in stateless mode.
  app.on(["GET", "DELETE"], "/mcp", (c) => {
    c.header("Allow", "POST");
    return c.json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null }, 405);
  });

  return app;
}

/** Returns the first scope a `tools/call` in the (possibly batched) JSON-RPC body needs but lacks. */
function missingScope(body: unknown, granted: string[]): string | undefined {
  for (const msg of Array.isArray(body) ? body : [body]) {
    const m = msg as { method?: unknown; params?: { name?: unknown } } | null;
    if (m?.method !== "tools/call" || typeof m.params?.name !== "string") continue;
    const needed = TOOL_SCOPES[m.params.name];
    if (needed && !granted.includes(needed)) return needed;
  }
  return undefined;
}

function challenge(c: Context, config: Config, status: 401 | 403, params: string) {
  c.header("WWW-Authenticate", `Bearer ${params}`);
  const error = status === 401 ? "unauthorized" : "insufficient_scope";
  return c.json({ error, resource: config.resource, scopes_supported: SUPPORTED_SCOPES }, status);
}
