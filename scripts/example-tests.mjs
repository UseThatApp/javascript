// Exercise every framework example end-to-end.
//
// For each example we:
//   1. Spin up a mock /licensing/getversion/ HTTP server.
//   2. Point the SDK at it via `configure({ api_url })`.
//   3. Build a real launch envelope with `buildPayload`.
//   4. POST the envelope to the example's /launch endpoint.
//   5. Assert the response body matches { user_key, version }.

import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { createServer as createHttpServer } from "node:http";

import {
  buildPayload,
  clearVersionCache,
  configure,
  resetConfig,
} from "../dist/index.js";

let passed = 0;
let failed = 0;

function ok(name) {
  passed++;
  console.log(`  ok   ${name}`);
}
function fail(name, err) {
  failed++;
  console.error(`  FAIL ${name}: ${err?.stack ?? err}`);
}
async function test(name, fn) {
  try {
    await fn();
    ok(name);
  } catch (e) {
    fail(name, e);
  }
}

function genKeypair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

const APP_ID = "11111111-2222-3333-4444-555555555555";
const market = genKeypair();
const developer = genKeypair();

function setupConfig(apiUrl) {
  resetConfig();
  clearVersionCache();
  configure({
    app_id: APP_ID,
    private_key: developer.privateKey,
    market_public_key: market.publicKey,
    api_url: apiUrl,
    clock_skew_seconds: 60,
    request_timeout_seconds: 5,
  });
}

function makeEnvelope(overrides = {}) {
  return buildPayload({
    user_key: "opaque-user-key-xyz",
    app_id: APP_ID,
    developer_public_key: developer.publicKey,
    market_private_key: market.privateKey,
    ...overrides,
  });
}

/** Spin up a mock /licensing/getversion/ that always returns `version`. */
async function withMockMarketplace(version, fn) {
  const server = createHttpServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ version, cache_seconds: 60 }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

async function startNodeServer(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    stop: async () => {
      server.close();
      await once(server, "close");
    },
  };
}

/** POST a launch envelope as application/x-www-form-urlencoded. */
async function postLaunch(baseUrl, envelope) {
  const body = new URLSearchParams({ uta_payload: envelope });
  return fetch(`${baseUrl}/launch`, {
    method: "POST",
    body,
    // URLSearchParams sets content-type automatically.
  });
}

async function assertOk(res, { user_key, version }) {
  if (res.status !== 200) {
    const text = await res.text();
    throw new Error(`status=${res.status} body=${text}`);
  }
  const body = await res.json();
  if (body.user_key !== user_key) {
    throw new Error(`user_key=${body.user_key}, want ${user_key}`);
  }
  if (body.version !== version) {
    throw new Error(`version=${body.version}, want ${version}`);
  }
}

// ──────────────────────────────────────────────────────────────────────
// node-http-min
// ──────────────────────────────────────────────────────────────────────

console.log("[1] node-http-min");

await test("POST /launch verifies envelope and returns version", async () => {
  await withMockMarketplace("Pro", async (marketUrl) => {
    setupConfig(marketUrl);
    const { createApp } = await import("../examples/node-http-min/app.mjs");
    const { url, stop } = await startNodeServer(createApp());
    try {
      const env = makeEnvelope({ user_key: "u-node" });
      const res = await postLaunch(url, env);
      await assertOk(res, { user_key: "u-node", version: "Pro" });
    } finally {
      await stop();
    }
  });
});

await test("POST /launch rejects a bad envelope with 400", async () => {
  await withMockMarketplace("Pro", async (marketUrl) => {
    setupConfig(marketUrl);
    const { createApp } = await import("../examples/node-http-min/app.mjs");
    const { url, stop } = await startNodeServer(createApp());
    try {
      const body = new URLSearchParams({ uta_payload: "not-a-real-envelope" });
      const res = await fetch(`${url}/launch`, { method: "POST", body });
      if (res.status !== 400) throw new Error(`status=${res.status}`);
    } finally {
      await stop();
    }
  });
});

// ──────────────────────────────────────────────────────────────────────
// express-min
// ──────────────────────────────────────────────────────────────────────

console.log("[2] express-min");

await test("POST /launch via utaLaunchView returns version", async () => {
  await withMockMarketplace("Free", async (marketUrl) => {
    setupConfig(marketUrl);
    const { createApp } = await import("../examples/express-min/app.mjs");
    const server = createApp().listen(0, "127.0.0.1");
    await once(server, "listening");
    const { port } = server.address();
    const url = `http://127.0.0.1:${port}`;
    try {
      const env = makeEnvelope({ user_key: "u-express" });
      const res = await postLaunch(url, env);
      await assertOk(res, { user_key: "u-express", version: "Free" });
    } finally {
      server.close();
      await once(server, "close");
    }
  });
});

await test("POST /launch with bad envelope returns 400", async () => {
  await withMockMarketplace("Free", async (marketUrl) => {
    setupConfig(marketUrl);
    const { createApp } = await import("../examples/express-min/app.mjs");
    const server = createApp().listen(0, "127.0.0.1");
    await once(server, "listening");
    const { port } = server.address();
    try {
      const body = new URLSearchParams({ uta_payload: "not-real" });
      const res = await fetch(`http://127.0.0.1:${port}/launch`, {
        method: "POST",
        body,
      });
      if (res.status !== 400) throw new Error(`status=${res.status}`);
    } finally {
      server.close();
      await once(server, "close");
    }
  });
});

// ──────────────────────────────────────────────────────────────────────
// fastify-min
// ──────────────────────────────────────────────────────────────────────

console.log("[3] fastify-min");

await test("POST /launch returns version", async () => {
  await withMockMarketplace("Team", async (marketUrl) => {
    setupConfig(marketUrl);
    const { buildApp } = await import("../examples/fastify-min/app.mjs");
    const app = await buildApp();
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    const url = `http://127.0.0.1:${address.port}`;
    try {
      const env = makeEnvelope({ user_key: "u-fastify" });
      const res = await postLaunch(url, env);
      await assertOk(res, { user_key: "u-fastify", version: "Team" });
    } finally {
      await app.close();
    }
  });
});

await test("POST /launch with bad envelope returns 400", async () => {
  await withMockMarketplace("Team", async (marketUrl) => {
    setupConfig(marketUrl);
    const { buildApp } = await import("../examples/fastify-min/app.mjs");
    const app = await buildApp();
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    try {
      const body = new URLSearchParams({ uta_payload: "garbage" });
      const res = await fetch(`http://127.0.0.1:${address.port}/launch`, {
        method: "POST",
        body,
      });
      if (res.status !== 400) throw new Error(`status=${res.status}`);
    } finally {
      await app.close();
    }
  });
});

// ──────────────────────────────────────────────────────────────────────
// nextjs-min (App Router — call the route handler directly)
// ──────────────────────────────────────────────────────────────────────

console.log("[4] nextjs-min");

await test("POST handler verifies a Request and returns Response", async () => {
  await withMockMarketplace("Enterprise", async (marketUrl) => {
    setupConfig(marketUrl);
    const { POST } = await import(
      "../examples/nextjs-min/app/api/launch/route.mjs"
    );
    const env = makeEnvelope({ user_key: "u-next" });
    const body = new URLSearchParams({ uta_payload: env });
    const request = new Request("http://x/api/launch", {
      method: "POST",
      body,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    const response = await POST(request);
    if (response.status !== 200) {
      throw new Error(`status=${response.status} body=${await response.text()}`);
    }
    const data = await response.json();
    if (data.user_key !== "u-next") throw new Error(`user_key=${data.user_key}`);
    if (data.version !== "Enterprise") throw new Error(`version=${data.version}`);
  });
});

await test("POST handler handles JSON content-type", async () => {
  await withMockMarketplace("Pro", async (marketUrl) => {
    setupConfig(marketUrl);
    const { POST } = await import(
      "../examples/nextjs-min/app/api/launch/route.mjs"
    );
    const env = makeEnvelope({ user_key: "u-next-json" });
    const request = new Request("http://x/api/launch", {
      method: "POST",
      body: JSON.stringify({ uta_payload: env }),
      headers: { "content-type": "application/json" },
    });
    const response = await POST(request);
    if (response.status !== 200) {
      throw new Error(`status=${response.status}`);
    }
    const data = await response.json();
    if (data.user_key !== "u-next-json") throw new Error(`user_key=${data.user_key}`);
  });
});

await test("POST handler returns 400 for a bad envelope", async () => {
  await withMockMarketplace("Pro", async (marketUrl) => {
    setupConfig(marketUrl);
    const { POST } = await import(
      "../examples/nextjs-min/app/api/launch/route.mjs"
    );
    const body = new URLSearchParams({ uta_payload: "not-json" });
    const request = new Request("http://x/api/launch", { method: "POST", body });
    const response = await POST(request);
    if (response.status !== 400) throw new Error(`status=${response.status}`);
  });
});

// ──────────────────────────────────────────────────────────────────────
// nuxt-min (host the h3 event handler in a standalone h3 app)
// ──────────────────────────────────────────────────────────────────────

console.log("[5] nuxt-min");

await test("server route via standalone h3 returns version", async () => {
  await withMockMarketplace("Pro", async (marketUrl) => {
    setupConfig(marketUrl);
    const { createApp, toNodeListener, eventHandler } = await import("h3");
    const handler = (
      await import("../examples/nuxt-min/server/api/launch.post.mjs")
    ).default;

    // Mount the handler at /launch (the marketplace would POST to Nuxt's
    // auto-routed /api/launch; we strip the prefix here for a flat URL).
    const h3app = createApp();
    h3app.use("/launch", eventHandler(handler));

    const server = createHttpServer(toNodeListener(h3app));
    const { url, stop } = await startNodeServer(server);
    try {
      const env = makeEnvelope({ user_key: "u-nuxt" });
      const res = await postLaunch(url, env);
      await assertOk(res, { user_key: "u-nuxt", version: "Pro" });
    } finally {
      await stop();
    }
  });
});

await test("server route returns 400 for a bad envelope", async () => {
  await withMockMarketplace("Pro", async (marketUrl) => {
    setupConfig(marketUrl);
    const { createApp, toNodeListener, eventHandler } = await import("h3");
    const handler = (
      await import("../examples/nuxt-min/server/api/launch.post.mjs")
    ).default;

    const h3app = createApp();
    h3app.use("/launch", eventHandler(handler));

    const server = createHttpServer(toNodeListener(h3app));
    const { url, stop } = await startNodeServer(server);
    try {
      const body = new URLSearchParams({ uta_payload: "not-real" });
      const res = await fetch(`${url}/launch`, { method: "POST", body });
      if (res.status !== 400) throw new Error(`status=${res.status}`);
    } finally {
      await stop();
    }
  });
});

// ──────────────────────────────────────────────────────────────────────

console.log("");
console.log(`results: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
