// v2 (OIDC) SDK tests — node:test, importing the built dist.
// Mocks global fetch and mints signed ID tokens with jose.
import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import {
  beginLogin,
  completeLogin,
  configure,
  getEntitlement,
  logoutUrl,
  refresh,
  resetConfig,
  resetDiscoveryCache,
  UtaAuthError,
  UtaPermissionError,
  UtaServerError,
  UtaTokenError,
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
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes("/.well-known/openid-configuration")) return json(200, META);
    if (u === META.jwks_uri) return json(200, { keys: [keys.publicJwk] });
    if (u === META.token_endpoint) return routes.token();
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

for (const [status, ctor] of [[401, UtaTokenError], [403, UtaPermissionError], [500, UtaServerError]]) {
  test(`getEntitlement maps ${status}`, async () => {
    routes.entitlement = () => json(status, "nope");
    await assert.rejects(getEntitlement("at-123"), ctor);
  });
}

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

test("logoutUrl builds the end-session URL", async () => {
  const url = new URL(await logoutUrl({ idToken: "idt", postLogoutRedirectUri: "https://app.test.example/bye" }));
  assert.equal(url.origin + url.pathname, META.end_session_endpoint);
  assert.equal(url.searchParams.get("id_token_hint"), "idt");
  assert.equal(url.searchParams.get("post_logout_redirect_uri"), "https://app.test.example/bye");
  assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
});
