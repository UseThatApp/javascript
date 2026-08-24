// v2 (OIDC) SDK tests — node:test, importing the built dist.
// Mocks global fetch and mints signed ID tokens with jose.
import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import {
  beginLogin,
  completeLogin,
  configure,
  getEntitlement,
  logoutUrl,
  refresh,
  resetConfig,
  userinfo,
  resetDiscoveryCache,
  UtaAuthError,
  UtaConfigError,
  UtaDiscoveryError,
  UtaError,
  UtaPermissionError,
  UtaServiceNotEnabledError,
  UtaServerError,
  UtaTokenError,
  SDK_VERSION,
} from "../dist/index.js";

const ISSUER = "https://oidc.test.example/o";
const API_URL = "https://api.test.example";
const CLIENT_ID = "client-test-123";
const CLIENT_SECRET = "secret-xyz";
const REDIRECT_URI = "https://app.test.example/callback";
const META = {
  issuer: ISSUER,
  authorization_endpoint: ISSUER + "/authorize/",
  token_endpoint: ISSUER + "/token/",
  jwks_uri: ISSUER + "/.well-known/jwks.json",
  userinfo_endpoint: ISSUER + "/userinfo/",
  end_session_endpoint: ISSUER + "/logout/",
};

let keys; // { privateKey, publicJwk }

async function ensureKeys() {
  if (keys) return keys;
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "test-key-1";
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  keys = { privateKey, publicJwk };
  return keys;
}

async function makeIdToken({ sub = "pairwise-sub-abc", nonce = "test-nonce", aud = CLIENT_ID, exp = "1h" } = {}) {
  const { privateKey } = await ensureKeys();
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
    .setSubject(sub)
    .setIssuer(ISSUER)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(privateKey);
}

function json(status, body, headers = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

let routes;

function installFetch() {
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.includes("/.well-known/openid-configuration")) return json(200, META);
    if (u === META.jwks_uri) return json(200, { keys: [keys.publicJwk] });
    if (u === META.token_endpoint) return routes.token(init);
    if (u === META.userinfo_endpoint) return routes.userinfo();
    if (u.startsWith(API_URL + "/licensing/entitlement/")) return routes.entitlement();
    throw new Error("unexpected fetch: " + u);
  };
}

beforeEach(async () => {
  await ensureKeys();
  resetConfig();
  resetDiscoveryCache();
  configure({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    issuer: ISSUER,
    api_url: API_URL,
  });
  routes = {
    token: () => json(200, {}),
    userinfo: () => json(200, {}),
    entitlement: () => json(200, {}),
  };
  installFetch();
});

// ── beginLogin ────────────────────────────────────────────────────────

test("beginLogin builds a PKCE authorize URL + flowState", async () => {
  const { authorizationUrl, flowState } = await beginLogin();
  const url = new URL(authorizationUrl);
  assert.equal(url.origin + url.pathname, META.authorization_endpoint);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(url.searchParams.get("redirect_uri"), REDIRECT_URI);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.match(url.searchParams.get("scope"), /openid/);
  assert.equal(url.searchParams.get("state"), flowState.state);
  assert.equal(url.searchParams.get("nonce"), flowState.nonce);
  assert.ok(flowState.codeVerifier && flowState.redirectUri === REDIRECT_URI);
});

test("beginLogin state/verifier are random per call", async () => {
  const a = await beginLogin();
  const b = await beginLogin();
  assert.notEqual(a.flowState.state, b.flowState.state);
  assert.notEqual(a.flowState.codeVerifier, b.flowState.codeVerifier);
});

test("beginLogin allows benign extraParams", async () => {
  const { authorizationUrl } = await beginLogin({ extraParams: { ui_locales: "de" } });
  assert.equal(new URL(authorizationUrl).searchParams.get("ui_locales"), "de");
});

test("beginLogin rejects extraParams that override reserved params", async () => {
  for (const key of ["state", "nonce", "code_challenge", "redirect_uri", "client_id"]) {
    await assert.rejects(
      beginLogin({ extraParams: { [key]: "attacker" } }),
      (e) => e instanceof UtaError && e.message.includes(key),
    );
  }
});

// ── completeLogin ─────────────────────────────────────────────────────

function flow(overrides = {}) {
  return { state: "st", nonce: "test-nonce", codeVerifier: "v", redirectUri: REDIRECT_URI, ...overrides };
}

test("completeLogin success", async () => {
  const idToken = await makeIdToken({ nonce: "test-nonce" });
  routes.token = () => json(200, {
    access_token: "at-123", refresh_token: "rt-456", id_token: idToken,
    token_type: "Bearer", expires_in: 1800, scope: "openid entitlements",
  });
  const s = await completeLogin({ code: "abc", state: "st", flowState: flow() });
  assert.equal(s.sub, "pairwise-sub-abc");
  assert.equal(s.access_token, "at-123");
  assert.equal(s.refresh_token, "rt-456");
  assert.ok(s.expires_at > 0);
});

test("completeLogin rejects state mismatch", async () => {
  await assert.rejects(
    completeLogin({ code: "abc", state: "WRONG", flowState: flow() }),
    UtaAuthError,
  );
});

test("completeLogin rejects flowState with a missing nonce", async () => {
  const { nonce, ...withoutNonce } = flow();
  await assert.rejects(
    completeLogin({ code: "abc", state: "st", flowState: withoutNonce }),
    UtaAuthError,
  );
});

test("discovery rejects a document whose issuer does not match the configured issuer", async () => {
  configure({ issuer: "https://evil.test.example/o" });
  await assert.rejects(beginLogin(), UtaDiscoveryError);
});

test("completeLogin rejects nonce mismatch", async () => {
  const idToken = await makeIdToken({ nonce: "DIFFERENT" });
  routes.token = () => json(200, { access_token: "at", id_token: idToken, expires_in: 1800 });
  await assert.rejects(
    completeLogin({ code: "abc", state: "st", flowState: flow({ nonce: "expected" }) }),
    UtaTokenError,
  );
});

test("completeLogin rejects expired id token", async () => {
  const idToken = await makeIdToken({ nonce: "test-nonce", exp: Math.floor(Date.now() / 1000) - 300 });
  routes.token = () => json(200, { access_token: "at", id_token: idToken, expires_in: 1800 });
  await assert.rejects(
    completeLogin({ code: "abc", state: "st", flowState: flow() }),
    UtaTokenError,
  );
});

test("completeLogin rejects wrong audience", async () => {
  const idToken = await makeIdToken({ nonce: "test-nonce", aud: "someone-else" });
  routes.token = () => json(200, { access_token: "at", id_token: idToken, expires_in: 1800 });
  await assert.rejects(
    completeLogin({ code: "abc", state: "st", flowState: flow() }),
    UtaTokenError,
  );
});

test("completeLogin maps token endpoint error", async () => {
  routes.token = () => json(400, { error: "invalid_grant" });
  await assert.rejects(
    completeLogin({ code: "abc", state: "st", flowState: flow() }),
    (e) => e instanceof UtaTokenError && /invalid_grant/.test(e.message),
  );
});

// ── getEntitlement ────────────────────────────────────────────────────

test("getEntitlement returns a licensed entitlement", async () => {
  routes.entitlement = () => json(200, {
    entitled: true, version: "Pro", product_id: "p-1",
    status: "active", is_free: false, period_end: "2026-07-01",
  });
  const ent = await getEntitlement("at-123");
  assert.equal(ent.entitled, true);
  assert.equal(ent.version, "Pro");
  assert.equal(ent.product_id, "p-1");
  assert.equal(ent.status, "active");
  assert.equal(ent.is_free, false);
  assert.equal(ent.period_end, "2026-07-01");
});

test("getEntitlement returns a free entitlement", async () => {
  routes.entitlement = () => json(200, {
    entitled: true, version: "Free", product_id: "p-0", status: "free", is_free: true,
  });
  const ent = await getEntitlement("at-123");
  assert.equal(ent.is_free, true);
  assert.equal(ent.status, "free");
});

for (const [status, ctor] of [[401, UtaTokenError], [403, UtaPermissionError], [429, UtaServerError], [500, UtaServerError]]) {
  test(`getEntitlement maps ${status}`, async () => {
    routes.entitlement = () => json(status, "nope");
    await assert.rejects(getEntitlement("at-123"), ctor);
  });
}

test("getEntitlement maps 403 service_not_enabled to its own error", async () => {
  // The developer's to fix (enable the add-on) — must NOT read as a
  // scope problem, but must stay catchable as UtaPermissionError.
  routes.entitlement = () => json(403, {
    error: "service_not_enabled",
    error_description: "The developer has not enabled the entitlement service for this app.",
  });
  await assert.rejects(getEntitlement("at-123"), UtaServiceNotEnabledError);
  await assert.rejects(getEntitlement("at-123"), UtaPermissionError);
  // Glassbox F-10: the message names the CURRENT public feature name.
  // Code review (Python finding 10, same bug here — reversing F-10's
  // host half): the manage hub lives on the production dashboard host;
  // the configured api_url may be a dev stack with no manage UI, so the
  // message must NOT point there.
  await assert.rejects(getEntitlement("at-123"), /Hosted sign-in/);
  await assert.rejects(getEntitlement("at-123"), (err) => {
    assert.ok(!String(err.message).includes("Auth & Entitlement"));
    assert.ok(String(err.message).includes("https://www.usethatapp.com"));
    assert.ok(!String(err.message).includes(API_URL));
    return true;
  });
});

test("non-JSON error bodies are collapsed and capped (Glassbox F-11)", async () => {
  const htmlPage = "<!DOCTYPE html><html>" + "x".repeat(5000) + "</html>";
  routes.entitlement = () => json(500, htmlPage, { "content-type": "text/html" });
  await assert.rejects(getEntitlement("at-123"), (err) => {
    assert.ok(err instanceof UtaServerError);
    assert.ok(String(err.message).length < 400, `message too long: ${err.message.length}`);
    assert.ok(String(err.message).includes("truncated"));
    return true;
  });
});

test("getEntitlement keeps the exact class for a scope 403", async () => {
  routes.entitlement = () => json(403, { error: "insufficient_scope", scope: "entitlements" });
  try {
    await getEntitlement("at-123");
    assert.fail("expected a rejection");
  } catch (err) {
    assert.equal(err.constructor, UtaPermissionError);
  }
});

test("non-positive UTA_REQUEST_TIMEOUT_SECONDS is a config error", async () => {
  configure({ request_timeout_seconds: 0 });
  await assert.rejects(getEntitlement("at-123"), UtaConfigError);
});

// ── refresh / logout ──────────────────────────────────────────────────

test("refresh with a new id token", async () => {
  const idToken = await makeIdToken();
  routes.token = () => json(200, {
    access_token: "at-new", refresh_token: "rt-new", id_token: idToken,
    token_type: "Bearer", expires_in: 1800,
  });
  const s = await refresh("rt-456");
  assert.equal(s.access_token, "at-new");
  assert.equal(s.refresh_token, "rt-new");
  assert.equal(s.sub, "pairwise-sub-abc");
});

test("refresh without id token falls back to userinfo + carries refresh token forward", async () => {
  routes.token = () => json(200, { access_token: "at-new", token_type: "Bearer", expires_in: 1800 });
  routes.userinfo = () => json(200, { sub: "pairwise-sub-abc" });
  const s = await refresh("rt-456");
  assert.equal(s.sub, "pairwise-sub-abc");
  assert.equal(s.refresh_token, "rt-456");
});

test("refresh rejects a userinfo response missing sub", async () => {
  routes.token = () => json(200, { access_token: "at-new", token_type: "Bearer", expires_in: 1800 });
  routes.userinfo = () => json(200, {});
  await assert.rejects(refresh("rt-456"), UtaTokenError);
});

test("refresh surfaces a userinfo 403 instead of treating the error body as claims", async () => {
  routes.token = () => json(200, { access_token: "at-new", token_type: "Bearer", expires_in: 1800 });
  routes.userinfo = () => json(403, { detail: "missing scope" });
  await assert.rejects(refresh("rt-456"), UtaPermissionError);
});

test("empty UTA_CLIENT_SECRET falls through to UTA_CLIENT_SECRET_PATH", async () => {
  const secretPath = join(mkdtempSync(join(tmpdir(), "uta-test-")), "secret");
  writeFileSync(secretPath, "file-secret\n");
  configure({ client_secret: "", client_secret_path: secretPath });
  const idToken = await makeIdToken({ nonce: "test-nonce" });
  let auth;
  routes.token = (init) => {
    auth = init.headers.Authorization;
    return json(200, { access_token: "at", id_token: idToken, expires_in: 1800 });
  };
  await completeLogin({ code: "abc", state: "st", flowState: flow() });
  assert.equal(auth, "Basic " + Buffer.from(`${CLIENT_ID}:file-secret`).toString("base64"));
});

test("logoutUrl builds the end-session URL", async () => {
  const url = new URL(await logoutUrl({ idToken: "idt", postLogoutRedirectUri: "https://app.test.example/bye" }));
  assert.equal(url.origin + url.pathname, META.end_session_endpoint);
  assert.equal(url.searchParams.get("id_token_hint"), "idt");
  assert.equal(url.searchParams.get("post_logout_redirect_uri"), "https://app.test.example/bye");
  assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
});

// ── Quiver audit fixes (J-05, J-08, J-12) ──────────────────────────────

test("configure() rejects unknown option names (J-08, Python parity)", () => {
  assert.throws(
    () => configure({ api_ur: "http://typo.example" }),
    (err) => {
      assert.ok(err instanceof UtaConfigError);
      assert.match(err.message, /unknown configure\(\) option/);
      assert.match(err.message, /api_ur/);
      return true;
    },
  );
  // The typo must not have been stored either.
  configure({ api_url: "https://kept.example" });
});

test("a 429 surfaces Retry-After on UtaServerError (J-05)", async () => {
  routes.entitlement = () => json(429, { error: "rate_limited" }, { "retry-after": "60" });
  await assert.rejects(getEntitlement("at-123"), (err) => {
    assert.ok(err instanceof UtaServerError);
    assert.equal(err.retryAfter, 60);
    return true;
  });
});

test("retryAfter is null when the server sends none (J-05)", async () => {
  routes.entitlement = () => json(503, "unavailable");
  await assert.rejects(getEntitlement("at-123"), (err) => {
    assert.ok(err instanceof UtaServerError);
    assert.equal(err.retryAfter, null);
    return true;
  });
});

test("SDK_VERSION is exported and matches package.json (J-12)", async () => {
  const { readFileSync } = await import("node:fs");
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(SDK_VERSION, pkg.version);
});

// ── Pre-release code-review regressions ──────────────────────────────

test("entitlement product_id falls back to product_public_id (finding 1)", async () => {
  // The types.ts alias promise ("either works") must hold against a
  // server that predates the identifier cutover — same fallback the
  // LicenseState parser has.
  routes.entitlement = () => json(200, {
    entitled: true,
    version: "Pro",
    status: "active",
    product_public_id: "prod_abc123",
    // no product_id field at all
  });
  const ent = await getEntitlement("at-123");
  assert.equal(ent.product_id, "prod_abc123");
  assert.equal(ent.product_id, ent.product_public_id);
});

test("userinfo 429 is retriable with retryAfter (finding 2)", async () => {
  routes.userinfo = () => json(429, "rate limited", { "retry-after": "30" });
  await assert.rejects(userinfo("at-123"), (err) => {
    assert.ok(err instanceof UtaServerError);
    assert.equal(err.retryAfter, 30);
    return true;
  });
});

test("token endpoint 429 is not a credential failure (finding 2)", async () => {
  // A throttled refresh must NOT be UtaTokenError — callers treat that
  // as "log the user out" instead of backing off.
  routes.token = () => json(429, "rate limited", { "retry-after": "15" });
  await assert.rejects(refresh("rt-123"), (err) => {
    assert.ok(err instanceof UtaServerError);
    assert.ok(!(err instanceof UtaTokenError));
    assert.equal(err.retryAfter, 15);
    return true;
  });
});

test("large JSON error bodies are capped too (finding 3)", async () => {
  // JSON gets no exemption from the ~200-char cap: a gateway error with
  // an embedded multi-KB field is the log-flooding the cap exists for.
  const bigJson = JSON.stringify({ detail: "Traceback ".repeat(600) });
  routes.entitlement = () => json(500, bigJson);
  await assert.rejects(getEntitlement("at-123"), (err) => {
    assert.ok(String(err.message).length < 300);
    assert.ok(String(err.message).includes("truncated"));
    return true;
  });
});

test("configured client_secret_path outranks env UTA_CLIENT_SECRET (precedence)", async () => {
  // Python review finding 2, same bug here: secret-pair precedence is
  // per LAYER — a configure() override of either half must outrank both
  // env vars.
  const secretPath = join(mkdtempSync(join(tmpdir(), "uta-test-")), "secret");
  writeFileSync(secretPath, "fresh-file-secret\n");
  process.env.UTA_CLIENT_SECRET = "stale-env-secret";
  try {
    resetConfig();
    configure({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      issuer: ISSUER,
      api_url: API_URL,
      client_secret_path: secretPath,
    });
    const { loadConfig } = await import("../dist/index.js");
    assert.equal(loadConfig(true).client_secret, "fresh-file-secret");
  } finally {
    delete process.env.UTA_CLIENT_SECRET;
  }
});
