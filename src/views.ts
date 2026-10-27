/** Server-rendered pages for the authorization endpoint. No templates, no client JS. */

const SCOPE_LABELS: Record<string, string> = {
  "notes:read": "Read your notes",
  "notes:write": "Create notes on your behalf",
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: Canvas; }
  main { width: min(380px, calc(100% - 32px)); padding: 28px; border: 1px solid #8884; border-radius: 12px; }
  h1 { font-size: 1.25rem; margin: 0 0 8px; }
  p, li { line-height: 1.5; }
  label { display: block; margin-top: 12px; font-size: .9rem; }
  input { width: 100%; box-sizing: border-box; padding: 8px; margin-top: 4px; font: inherit; }
  .actions { display: flex; gap: 8px; margin-top: 20px; }
  button { flex: 1; padding: 10px; font: inherit; cursor: pointer; border-radius: 8px; border: 1px solid #8886; }
  button[value=approve] { background: #2563eb; color: white; border-color: #2563eb; }
  .error { color: #dc2626; }
  code { font-size: .85em; word-break: break-all; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

export function consentPage(p: {
  requestId: string;
  clientName: string;
  redirectUri: string;
  scopes: string[];
  error?: string;
}): string {
  const scopes = p.scopes.map((s) => `<li>${escapeHtml(SCOPE_LABELS[s] ?? s)} <code>${escapeHtml(s)}</code></li>`);
  return layout(
    "Authorize access",
    `<h1>Authorize ${escapeHtml(p.clientName)}</h1>
<p>This application wants to:</p>
<ul>${scopes.join("")}</ul>
<p>You will be sent back to <code>${escapeHtml(p.redirectUri)}</code>.</p>
${p.error ? `<p class="error" role="alert">${escapeHtml(p.error)}</p>` : ""}
<form method="post" action="/authorize">
  <input type="hidden" name="request_id" value="${escapeHtml(p.requestId)}">
  <label>Username <input name="username" autocomplete="username" required autofocus></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <div class="actions">
    <button name="decision" value="deny" formnovalidate>Deny</button>
    <button name="decision" value="approve">Approve</button>
  </div>
</form>`,
  );
}

export function errorPage(message: string): string {
  return layout(
    "Authorization error",
    `<h1>Authorization error</h1><p class="error">${escapeHtml(message)}</p>
<p>Return to the application and start the connection again.</p>`,
  );
}
