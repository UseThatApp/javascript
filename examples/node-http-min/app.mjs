// Minimal launch endpoint built on Node's built-in http module — no
// framework. Demonstrates the framework-agnostic API:
// `getUser` + `getVersion`.

import { createServer } from "node:http";

import { getUser, getVersion, UtaError } from "usethatapp";

async function readBody(req) {
  let chunks = "";
  for await (const chunk of req) chunks += chunk;
  return chunks;
}

function extractPayload(contentType, body) {
  if (contentType.includes("application/json")) {
    return JSON.parse(body).uta_payload;
  }
  // default: application/x-www-form-urlencoded (what the marketplace posts)
  return Object.fromEntries(new URLSearchParams(body)).uta_payload;
}

export function createApp() {
  return createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/launch") {
      res.statusCode = 404;
      res.end();
      return;
    }
    try {
      const body = await readBody(req);
      const payload = extractPayload(req.headers["content-type"] ?? "", body);
      const user = getUser(payload);
      const version = await getVersion(user.user_key);
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ user_key: user.user_key, version }));
    } catch (e) {
      const status = e instanceof UtaError ? 400 : 500;
      res.statusCode = status;
      res.end(String(e?.message ?? e));
    }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => {
    console.log(`node-http-min listening on http://127.0.0.1:${port}`);
  });
}
