// End-to-end compatibility tests for the rewritten SDK.
//
// Covers:
//  * Launch envelope round-trip via buildPayload + getUser
//  * Rejection paths: tampered ct, tampered signature, expired exp,
//    mismatched app_id, wrong kind, malformed envelope.
//  * getVersion: signed request body, status-code → error mapping,
//    process-local TTL caching, useCache=false bypass.
//  * utaLaunchView: POST-only, 400 on bad payload, attaches req.utaUser.

import {
  constants,
  generateKeyPairSync,
  verify,
} from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createHttpServer } from "node:http";
import { once } from "node:events";

import {
  buildPayload,
  clearVersionCache,
  configure,
  getUserFromRequest,
  getUser,
  getVersion,
  resetConfig,
  utaLaunchView,
  UtaAppMismatchError,
  UtaBadRequestError,
  UtaError,
  UtaPayloadExpiredError,
  UtaServerError,
  UtaSessionRevokedError,
  UtaSignatureError,
  UtaUnknownSessionError,
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

function setupConfig({ apiUrl = "https://test.example", timeout = 5 } = {}) {
  resetConfig();
  clearVersionCache();
  configure({
    app_id: APP_ID,
    private_key: developer.privateKey,
    market_public_key: market.publicKey,
    api_url: apiUrl,
    clock_skew_seconds: 60,
    request_timeout_seconds: timeout,
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

// ──────────────────────────────────────────────────────────────────────
// Section 1: launch envelope round-trip + rejection paths
// ──────────────────────────────────────────────────────────────────────

console.log("[1] launch envelope");

setupConfig();

await test("round-trip: valid envelope returns matching UtaUser", () => {
  const env = makeEnvelope({ user_key: "abc-123", version_hint: "Pro" });
  const user = getUser(env);
  if (user.user_key !== "abc-123") throw new Error(`user_key=${user.user_key}`);
  if (user.app_id !== APP_ID) throw new Error(`app_id=${user.app_id}`);
  if (user.version_hint !== "Pro") throw new Error(`version_hint=${user.version_hint}`);
  if (typeof user.issued_at !== "number") throw new Error("issued_at not number");
  if (typeof user.expires_at !== "number") throw new Error("expires_at not number");
});

await test("accepts pre-parsed envelope object", () => {
  const env = JSON.parse(makeEnvelope());
  const user = getUser(env);
  if (user.user_key !== "opaque-user-key-xyz") throw new Error("user_key");
});

await test("version_hint missing → null", () => {
  const env = makeEnvelope();
  const user = getUser(env);
  if (user.version_hint !== null) throw new Error(`hint=${user.version_hint}`);
});

await test("rejects tampered ct (AES-GCM tag fails)", () => {
  const env = JSON.parse(makeEnvelope());
  // flip a hex nibble in the middle of ct (not the tag)
  const buf = Buffer.from(env.ct, "hex");
  buf[5] ^= 0x01;
  env.ct = buf.toString("hex");
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`wrong type ${e?.constructor?.name}`);
    if (!/AES-GCM|signature|tampered/i.test(e.message)) {
      // PSS covers ek||iv||ct, so tampering ct first trips signature verify.
      throw new Error(`unexpected msg ${e.message}`);
    }
  }
});

await test("rejects tampered signature", () => {
  const env = JSON.parse(makeEnvelope());
  const buf = Buffer.from(env.signature, "hex");
  buf[0] ^= 0xff;
  env.signature = buf.toString("hex");
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaSignatureError)) {
      throw new Error(`wrong type ${e?.constructor?.name}`);
    }
  }
});

await test("rejects expired exp", () => {
  // iat = 1000s in the past, exp_seconds = 60 → exp is 940s in the past,
  // well past the 60s clock-skew window.
  const past = Math.floor(Date.now() / 1000) - 1000;
  const env = makeEnvelope({ iat: past, exp_seconds: 60 });
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaPayloadExpiredError)) {
      throw new Error(`wrong type ${e?.constructor?.name}`);
    }
  }
});

await test("rejects mismatched app_id", () => {
  const env = makeEnvelope({ app_id: "99999999-9999-9999-9999-999999999999" });
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaAppMismatchError)) {
      throw new Error(`wrong type ${e?.constructor?.name}`);
    }
  }
});

await test("rejects wrong kind", () => {
  const env = makeEnvelope({ kind: "logout" });
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`wrong type ${e?.constructor?.name}`);
    if (!/kind/.test(e.message)) throw new Error(`msg=${e.message}`);
  }
});

await test("rejects malformed envelope (missing fields)", () => {
  try {
    getUser(JSON.stringify({ v: 1, alg: "x" }));
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`wrong type ${e?.constructor?.name}`);
    if (!/missing fields/.test(e.message)) throw new Error(`msg=${e.message}`);
  }
});

await test("rejects bad hex", () => {
  const env = JSON.parse(makeEnvelope());
  env.ek = "ZZZZ";
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`wrong type ${e?.constructor?.name}`);
  }
});

await test("rejects mismatched developer key (OAEP unwrap fails)", () => {
  const other = genKeypair();
  const env = buildPayload({
    user_key: "x",
    app_id: APP_ID,
    developer_public_key: other.publicKey, // encrypted to someone else
    market_private_key: market.privateKey,
  });
  try {
    getUser(env);
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`wrong type ${e?.constructor?.name}`);
  }
});

// ──────────────────────────────────────────────────────────────────────
// Section 2: getVersion against a mocked HTTP server
// ──────────────────────────────────────────────────────────────────────

console.log("[2] getVersion");

/** Spin up an http server that records requests and replies per script. */
async function withMockServer(handler, fn) {
  const server = createHttpServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => handler(req, res, raw));
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

await test("getVersion: signed body shape + version returned + cached", async () => {
  let calls = 0;
  let lastBody = null;
  await withMockServer(
    (req, res, raw) => {
      calls++;
      lastBody = JSON.parse(raw);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        version: "Pro",
        cache_until: Math.floor(Date.now() / 1000) + 60,
        cache_seconds: 60,
      }));
    },
    async (url) => {
      setupConfig({ apiUrl: url });
      const v1 = await getVersion("opaque-user-key-xyz");
      if (v1 !== "Pro") throw new Error(`v1=${v1}`);

      // shape checks on the recorded request
      if (lastBody.app_id !== APP_ID) throw new Error("app_id");
      if (lastBody.user_key !== "opaque-user-key-xyz") throw new Error("user_key");
      if (typeof lastBody.ts !== "number") throw new Error("ts");
      if (typeof lastBody.nonce !== "string" || lastBody.nonce.length !== 32) {
        throw new Error("nonce");
      }
      if (typeof lastBody.signature !== "string") throw new Error("signature");

      // canonical (sorted, compact) JSON should verify with developer pub key
      const canonical = JSON.stringify(
        {
          app_id: lastBody.app_id,
          nonce: lastBody.nonce,
          ts: lastBody.ts,
          user_key: lastBody.user_key,
        },
        ["app_id", "nonce", "ts", "user_key"],
      );
      const sigOk = verify(
        "sha256",
        Buffer.from(canonical, "utf8"),
        {
          key: developer.publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_AUTO,
        },
        Buffer.from(lastBody.signature, "hex"),
      );
      if (!sigOk) throw new Error("PSS signature did not verify");

      // second call within cache_until → no extra round trip
      const v2 = await getVersion("opaque-user-key-xyz");
      if (v2 !== "Pro") throw new Error(`v2=${v2}`);
      if (calls !== 1) throw new Error(`expected 1 call, got ${calls}`);

      // useCache:false forces a fresh round trip
      const v3 = await getVersion("opaque-user-key-xyz", { useCache: false });
      if (v3 !== "Pro") throw new Error(`v3=${v3}`);
      if (calls !== 2) throw new Error(`expected 2 calls, got ${calls}`);
    },
  );
});

await test("getVersion: fresh nonce per call", async () => {
  const nonces = new Set();
  await withMockServer(
    (req, res, raw) => {
      const body = JSON.parse(raw);
      nonces.add(body.nonce);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ version: "Free", cache_until: 0, cache_seconds: 0 }));
    },
    async (url) => {
      setupConfig({ apiUrl: url });
      for (let i = 0; i < 3; i++) {
        await getVersion(`key-${i}`); // distinct user_key so cache doesn't interfere
      }
    },
  );
  if (nonces.size !== 3) throw new Error(`expected 3 unique nonces, got ${nonces.size}`);
});

const statusMap = [
  [400, UtaBadRequestError],
  [401, UtaSignatureError],
  [403, UtaSessionRevokedError],
  [404, UtaUnknownSessionError],
  [500, UtaServerError],
  [503, UtaServerError],
];

for (const [status, errClass] of statusMap) {
  await test(`getVersion: ${status} → ${errClass.name}`, async () => {
    await withMockServer(
      (req, res) => {
        res.writeHead(status, { "content-type": "text/plain" });
        res.end(`error ${status}`);
      },
      async (url) => {
        setupConfig({ apiUrl: url });
        try {
          await getVersion("k");
          throw new Error("expected throw");
        } catch (e) {
          if (!(e instanceof errClass)) {
            throw new Error(`got ${e?.constructor?.name}, want ${errClass.name}`);
          }
        }
      },
    );
  });
}

await test("getVersion: returns null for unlicensed user", async () => {
  await withMockServer(
    (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ version: null, cache_seconds: 30 }));
    },
    async (url) => {
      setupConfig({ apiUrl: url });
      const v = await getVersion("k");
      if (v !== null) throw new Error(`v=${v}`);
    },
  );
});

// ──────────────────────────────────────────────────────────────────────
// Section 3: utaLaunchView (Express-style)
// ──────────────────────────────────────────────────────────────────────

console.log("[3] utaLaunchView");

function fakeRes() {
  return {
    statusCode: 200,
    headers: {},
    body: "",
    status(code) { this.statusCode = code; return this; },
    setHeader(name, val) { this.headers[name] = val; },
    send(b) { this.body = String(b); return this; },
    end(b) { if (b !== undefined) this.body = String(b); return this; },
  };
}

await test("utaLaunchView: POST + good envelope → handler runs with utaUser", async () => {
  setupConfig();
  const env = makeEnvelope({ user_key: "u-1" });
  const req = { method: "POST", body: { uta_payload: env } };
  const res = fakeRes();
  let seen = null;
  const mw = utaLaunchView((req, user) => {
    seen = user;
    res.status(204).end();
  });
  await mw(req, res);
  if (res.statusCode !== 204) throw new Error(`status=${res.statusCode}`);
  if (seen?.user_key !== "u-1") throw new Error(`user_key=${seen?.user_key}`);
  if (req.utaUser?.user_key !== "u-1") throw new Error("req.utaUser not set");
});

await test("utaLaunchView: non-POST → 405", async () => {
  setupConfig();
  const req = { method: "GET", body: {} };
  const res = fakeRes();
  let handlerCalled = false;
  const mw = utaLaunchView(() => { handlerCalled = true; });
  await mw(req, res);
  if (res.statusCode !== 405) throw new Error(`status=${res.statusCode}`);
  if (res.headers.Allow !== "POST") throw new Error(`Allow=${res.headers.Allow}`);
  if (handlerCalled) throw new Error("handler should not run");
});

await test("utaLaunchView: invalid payload → 400", async () => {
  setupConfig();
  const req = { method: "POST", body: { uta_payload: "not-a-real-envelope" } };
  const res = fakeRes();
  let handlerCalled = false;
  const mw = utaLaunchView(() => { handlerCalled = true; });
  await mw(req, res);
  if (res.statusCode !== 400) throw new Error(`status=${res.statusCode}`);
  if (!/invalid launch payload/.test(res.body)) throw new Error(`body=${res.body}`);
  if (handlerCalled) throw new Error("handler should not run");
});

await test("getUserFromRequest via request body works", async () => {
  setupConfig();
  const env = makeEnvelope({ user_key: "req-user" });
  const req = { body: { uta_payload: env } };
  const user = getUserFromRequest(req);
  if (user.user_key !== "req-user") throw new Error(`got ${user.user_key}`);
});

await test("getUserFromRequest: missing uta_payload throws UtaError", () => {
  setupConfig();
  try {
    getUserFromRequest({ body: {} });
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`got ${e?.constructor?.name}`);
  }
});

// ──────────────────────────────────────────────────────────────────────
// Section 4: key-file path loading (UTA_PRIVATE_KEY_PATH / UTA_MARKET_PUBLIC_KEY_PATH)
// ──────────────────────────────────────────────────────────────────────

console.log("[4] key file paths");

const KEY_DIR = mkdtempSync(join(tmpdir(), "uta-keys-"));
const PRIV_FILE = join(KEY_DIR, "priv.pem");
const PUB_FILE = join(KEY_DIR, "market.pub");
writeFileSync(PRIV_FILE, developer.privateKey, "utf8");
writeFileSync(PUB_FILE, market.publicKey, "utf8");

/** Reset config and use process.env only (no programmatic overrides). */
function setupConfigFromEnv(envOverrides) {
  resetConfig();
  clearVersionCache();
  for (const k of [
    "UTA_APP_ID",
    "UTA_PRIVATE_KEY",
    "UTA_PRIVATE_KEY_PATH",
    "UTA_MARKET_PUBLIC_KEY",
    "UTA_MARKET_PUBLIC_KEY_PATH",
    "UTA_API_URL",
  ]) {
    delete process.env[k];
  }
  process.env.UTA_APP_ID = APP_ID;
  process.env.UTA_API_URL = "https://test.example";
  Object.assign(process.env, envOverrides);
}

await test("loads private key from UTA_PRIVATE_KEY_PATH", () => {
  setupConfigFromEnv({
    UTA_PRIVATE_KEY_PATH: PRIV_FILE,
    UTA_MARKET_PUBLIC_KEY: market.publicKey,
  });
  const env = makeEnvelope({ user_key: "u-from-path" });
  const user = getUser(env);
  if (user.user_key !== "u-from-path") throw new Error(`got ${user.user_key}`);
});

await test("loads market public key from UTA_MARKET_PUBLIC_KEY_PATH", () => {
  setupConfigFromEnv({
    UTA_PRIVATE_KEY: developer.privateKey,
    UTA_MARKET_PUBLIC_KEY_PATH: PUB_FILE,
  });
  const env = makeEnvelope({ user_key: "u-pub-path" });
  const user = getUser(env);
  if (user.user_key !== "u-pub-path") throw new Error(`got ${user.user_key}`);
});

await test("both keys loaded from path env vars", () => {
  setupConfigFromEnv({
    UTA_PRIVATE_KEY_PATH: PRIV_FILE,
    UTA_MARKET_PUBLIC_KEY_PATH: PUB_FILE,
  });
  const env = makeEnvelope({ user_key: "u-both-paths" });
  const user = getUser(env);
  if (user.user_key !== "u-both-paths") throw new Error(`got ${user.user_key}`);
});

await test("direct env var wins over path env var", () => {
  // PATH points at a junk file; direct value is the real key. Direct must win.
  const junk = join(KEY_DIR, "junk.pem");
  writeFileSync(junk, "not-a-pem", "utf8");
  setupConfigFromEnv({
    UTA_PRIVATE_KEY: developer.privateKey,
    UTA_PRIVATE_KEY_PATH: junk,
    UTA_MARKET_PUBLIC_KEY: market.publicKey,
  });
  const env = makeEnvelope({ user_key: "u-direct-wins" });
  const user = getUser(env);
  if (user.user_key !== "u-direct-wins") throw new Error(`got ${user.user_key}`);
});

await test("missing key file → UtaError mentioning the path var", () => {
  setupConfigFromEnv({
    UTA_PRIVATE_KEY_PATH: join(KEY_DIR, "does-not-exist.pem"),
    UTA_MARKET_PUBLIC_KEY: market.publicKey,
  });
  try {
    getUser(makeEnvelope({ user_key: "x" }));
    throw new Error("expected throw");
  } catch (e) {
    if (!(e instanceof UtaError)) throw new Error(`got ${e?.constructor?.name}`);
    if (!/UTA_PRIVATE_KEY_PATH/.test(e.message)) {
      throw new Error(`unexpected message: ${e.message}`);
    }
  }
});

await test("neither key nor path set → error mentions both vars", () => {
  setupConfigFromEnv({
    UTA_MARKET_PUBLIC_KEY: market.publicKey,
  });
  try {
    getUser(makeEnvelope({ user_key: "x" }));
    throw new Error("expected throw");
  } catch (e) {
    if (!/UTA_PRIVATE_KEY or UTA_PRIVATE_KEY_PATH/.test(e.message)) {
      throw new Error(`unexpected message: ${e.message}`);
    }
  }
});

// ──────────────────────────────────────────────────────────────────────

console.log("");
console.log(`results: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
