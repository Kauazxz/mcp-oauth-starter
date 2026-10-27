import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error((err as Error).message);
  console.error("Copy .env.example to .env and fill it in.");
  process.exit(1);
}

const server = serve({ fetch: createApp({ config }).fetch, port: config.port }, () => {
  console.log(`Authorization server: ${config.issuer}`);
  console.log(`MCP endpoint:         ${config.resource}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
