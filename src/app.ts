import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Config } from "./config.js";
import { mcpRoutes } from "./mcp.js";
import { MemoryNotesStore, type NotesStore } from "./notes.js";
import { oauthRoutes } from "./oauth.js";
import { MemoryStore, type OAuthStore } from "./store.js";

export interface AppOptions {
  config: Config;
  store?: OAuthStore;
  notes?: NotesStore;
  /** Injectable clock (ms since epoch) so tests can fast-forward expirations. */
  now?: () => number;
}

/** Wires the authorization server and the MCP resource server into one Hono app. */
export function createApp({ config, now = Date.now, store = new MemoryStore(now), notes = new MemoryNotesStore() }: AppOptions) {
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
  });

  // Browser-based MCP clients (e.g. MCP Inspector) call discovery, registration, token and
  // /mcp directly. No cookies are involved, so a wildcard origin does not expose anything.
  const apiCors = cors({
    origin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type", "Mcp-Protocol-Version", "Mcp-Session-Id"],
    exposeHeaders: ["WWW-Authenticate", "Mcp-Session-Id", "Mcp-Protocol-Version"],
  });
  for (const path of ["/.well-known/*", "/register", "/token", "/mcp"]) app.use(path, apiCors);

  app.get("/", (c) =>
    c.json({ name: "mcp-oauth-starter", mcp_endpoint: config.resource, issuer: config.issuer }),
  );
  app.get("/healthz", (c) => c.json({ status: "ok" }));

  const deps = { config, store, now };
  app.route("/", oauthRoutes(deps));
  app.route("/", mcpRoutes(deps, notes));

  app.onError((err, c) => {
    console.error(err);
    return c.json({ error: "server_error", error_description: "Internal server error" }, 500);
  });

  return app;
}
