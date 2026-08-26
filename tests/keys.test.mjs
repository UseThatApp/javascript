// License Key API tests: bring-your-own-auth MoR verification.
import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";

import {
  configure,
  getOrder,
  regenerateLicenseKey,
  resetConfig,
  validateLicenseKey,
  UtaConfigError,
  UtaError,
  UtaLicenseCanceledError,
  UtaNotFoundError,
  UtaOrderProcessingError,
  UtaServerError,
} from "../dist/index.js";

const API_URL = "https://api.test.example";
const CLIENT_ID = "client-test-123";
const CLIENT_SECRET = "secret-xyz";
const LICENSE_ID = "11111111-2222-3333-4444-555555555555";

const STATE = {
  entitled: true,
  status: "active",
  license_id: LICENSE_ID,
  product_public_id: "prod_abc",
  period_end: "2026-09-19",
  canceled_at: null,
};

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

let routes;
let lastRequest;

beforeEach(() => {
  resetConfig();
  // Keys mode: deliberately NO redirect_uri — only id + secret.
  configure({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    api_url: API_URL,
  });
  routes = {};
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    lastRequest = { url: u, init };
    for (const [prefix, handler] of Object.entries(routes)) {
      if (u.startsWith(API_URL + prefix)) return handler(init);
    }
    throw new Error("unexpected fetch: " + u);
  };
});

function expectedBasic() {
  return "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
}

test("validateLicenseKey sends client credentials and parses the state", async () => {
  routes["/api/v1/licenses/validate"] = () => json(200, STATE);
  const state = await validateLicenseKey("key_abc");
  assert.equal(state.entitled, true);
  assert.equal(state.status, "active");
  assert.equal(state.license_id, LICENSE_ID);
  assert.equal(state.license_key, null);
  assert.equal(lastRequest.init.headers.Authorization, expectedBasic());
  assert.deepEqual(JSON.parse(lastRequest.init.body), { key: "key_abc" });
});

test("a canceled purchase is an answer, not an error", async () => {
  routes["/api/v1/licenses/validate"] = () =>
    json(200, { ...STATE, entitled: false, status: "canceled", canceled_at: "2026-08-20T00:00:00+00:00" });
  const state = await validateLicenseKey("key_abc");
  assert.equal(state.entitled, false);
  assert.equal(state.status, "canceled");
});

test("unknown key throws UtaNotFoundError with its code", async () => {
  routes["/api/v1/licenses/validate"] = () => json(404, { error: "unknown_key" });
  await assert.rejects(validateLicenseKey("key_bogus"), (e) => {
    assert.ok(e instanceof UtaNotFoundError);
    assert.equal(e.code, "unknown_key");
    return true;
  });
});

test("missing client secret is a config error", async () => {
  resetConfig();
  configure({ client_id: CLIENT_ID, api_url: API_URL });
  await assert.rejects(validateLicenseKey("key_abc"), UtaConfigError);
});

test("rejected credentials are a config error", async () => {
  routes["/api/v1/licenses/validate"] = () => json(401, { error: "invalid_client" });
  await assert.rejects(validateLicenseKey("key_abc"), UtaConfigError);
});

test("getOrder returns the key and urlencodes the ref", async () => {
  routes["/api/v1/orders/"] = () => json(200, { ...STATE, license_key: "key_new" });
  const state = await getOrder("a:b:c");
  assert.equal(state.license_key, "key_new");
  assert.ok(lastRequest.url.endsWith("/api/v1/orders/a%3Ab%3Ac"));
});

test("getOrder before the webhook lands says retry", async () => {
  routes["/api/v1/orders/"] = () => json(202, { status: "processing" });
  await assert.rejects(getOrder("REF"), UtaOrderProcessingError);
});

test("getOrder with a bad ref is unknown_order", async () => {
  routes["/api/v1/orders/"] = () => json(404, { error: "unknown_order" });
  await assert.rejects(getOrder("BAD"), (e) => {
    assert.ok(e instanceof UtaNotFoundError);
    assert.equal(e.code, "unknown_order");
    return true;
  });
});

test("regenerateLicenseKey returns the new key once", async () => {
  routes[`/api/v1/licenses/${LICENSE_ID}/regenerate-key`] = () =>
    json(200, { ...STATE, license_key: "key_rotated", rotated_at: "2026-08-20T01:02:03+00:00" });
  const state = await regenerateLicenseKey(LICENSE_ID);
  assert.equal(state.license_key, "key_rotated");
  assert.ok(state.rotated_at);
});

test("regenerating a canceled license throws", async () => {
  routes[`/api/v1/licenses/${LICENSE_ID}/regenerate-key`] = () =>
    json(409, { error: "license_canceled" });
  await assert.rejects(regenerateLicenseKey(LICENSE_ID), UtaLicenseCanceledError);
});

test("server errors are retriable UtaServerError", async () => {
  routes["/api/v1/licenses/validate"] = () => json(503, "down");
  await assert.rejects(validateLicenseKey("key_abc"), UtaServerError);
});

test("empty inputs are rejected locally", async () => {
  await assert.rejects(validateLicenseKey(""), UtaError);
  await assert.rejects(getOrder(""), UtaError);
  await assert.rejects(regenerateLicenseKey(""), UtaError);
});

test("product_id is an equal-valued alias of product_public_id", async () => {
  // Post-cutover pair — same contract as the entitlement endpoint.
  routes["/api/v1/licenses/validate"] = () =>
    json(200, { ...STATE, product_id: STATE.product_public_id });
  const state = await validateLicenseKey("key_abc");
  assert.equal(state.product_id, state.product_public_id);
  assert.ok(state.product_id.startsWith("prod_"));
});

test("product_id falls back against a pre-cutover server", async () => {
  routes["/api/v1/licenses/validate"] = () => json(200, STATE);
  const state = await validateLicenseKey("key_abc");
  assert.equal(state.product_id, STATE.product_public_id);
});

// ── Pre-release code-review regressions ──────────────────────────────

test("a JSON array response throws instead of decoding to defaults (finding 4)", async () => {
  // The old hand-rolled decode lacked the Array.isArray rejection:
  // typeof [] === "object", every per-field guard fell through, and
  // validateLicenseKey returned {entitled: false} — a silent
  // entitlement denial instead of a loud contract error.
  routes["/api/v1/licenses/validate"] = () => json(200, [STATE]);
  await assert.rejects(validateLicenseKey("key_x"), (err) => {
    assert.ok(err instanceof UtaError);
    assert.ok(/not a JSON object/.test(err.message));
    return true;
  });
});

test("202 semantics belong to getOrder alone (finding 9)", async () => {
  // getOrder: 202 = payment cleared, license pending — retriable.
  routes["/api/v1/orders/"] = () => json(202, {});
  await assert.rejects(getOrder("ref-1"), UtaOrderProcessingError);
  // validateLicenseKey: a 202 is off-contract — the order-specific
  // "retry in a few seconds" message must not steer retry loops here.
  routes["/api/v1/licenses/validate"] = () => json(202, {});
  await assert.rejects(validateLicenseKey("key_x"), (err) => {
    assert.ok(!(err instanceof UtaOrderProcessingError));
    assert.ok(/unexpected status 202/.test(err.message));
    return true;
  });
});
