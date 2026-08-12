// Purchase-support tests (v2.1) — node:test, importing the built dist.
// Covers the pure URL builders and the anonymous public pricing API.
import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";

import {
  configure,
  getAppInfo,
  getPrices,
  manageUrl,
  purchaseUrl,
  resetConfig,
  UtaConfigError,
  UtaError,
  UtaServerError,
} from "../dist/index.js";

const API_URL = "https://api.test.example";
const CLIENT_ID = "client-test-123";
const REDIRECT_URI = "https://app.test.example/callback";
const APP_INFO_URL = `${API_URL}/api/v1/public/apps/${CLIENT_ID}/`;
const PRICES_URL = `${API_URL}/api/v1/public/apps/${CLIENT_ID}/prices/`;

function json(status, body, headers = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

let routes;
let lastRequest;

function installFetch() {
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    lastRequest = { url: u, init };
    if (u === APP_INFO_URL) return routes.appInfo();
    if (u === PRICES_URL) return routes.prices();
    throw new Error("unexpected fetch: " + u);
  };
}

beforeEach(() => {
  resetConfig();
  configure({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    api_url: API_URL,
  });
  routes = {
    appInfo: () => json(200, {}),
    prices: () => json(200, {}),
  };
  lastRequest = null;
  installFetch();
});

// ── purchaseUrl ───────────────────────────────────────────────────────

test("purchaseUrl builds the bare buy URL", () => {
  assert.equal(purchaseUrl("prc_abc123"), `${API_URL}/buy/prc_abc123/`);
});

test("purchaseUrl needs no config at all (defaults to production)", () => {
  // A pricing-only integration (e.g. a marketing page) sets no OIDC
  // config; the builder must not demand UTA_REDIRECT_URI or UTA_CLIENT_ID.
  resetConfig();
  assert.equal(
    purchaseUrl("prc_abc123"),
    "https://www.usethatapp.com/buy/prc_abc123/",
  );
});

test("getPrices works without OIDC config (client_id + defaults only)", async () => {
  resetConfig();
  configure({ client_id: CLIENT_ID, api_url: API_URL });
  routes.prices = () =>
    json(200, {
      client_id: CLIENT_ID,
      app_name: "App",
      has_free_tier: false,
      prices: [],
    });
  const prices = await getPrices();
  assert.equal(prices.app_name, "App");
});

test("purchaseUrl appends next, ref, email in order", () => {
  const url = purchaseUrl("prc_abc123", {
    next: "https://app.test.example/thanks",
    ref: "AFF42",
    email: "buyer@example.com",
  });
  assert.equal(
    url,
    `${API_URL}/buy/prc_abc123/` +
      "?next=https%3A%2F%2Fapp.test.example%2Fthanks&ref=AFF42&email=buyer%40example.com",
  );
});

test("purchaseUrl encodes special characters in next", () => {
  const url = new URL(purchaseUrl("prc_abc123", { next: "https://app.test.example/a?b=1&c=2 3" }));
  assert.equal(url.searchParams.get("next"), "https://app.test.example/a?b=1&c=2 3");
  assert.equal([...url.searchParams.keys()].length, 1);
});

test("purchaseUrl omits absent params", () => {
  assert.equal(
    purchaseUrl("prc_abc123", { ref: "AFF42" }),
    `${API_URL}/buy/prc_abc123/?ref=AFF42`,
  );
});

for (const bad of ["", "   "]) {
  test(`purchaseUrl rejects ${JSON.stringify(bad)} priceId`, () => {
    assert.throws(() => purchaseUrl(bad), UtaError);
  });
}

// ── manageUrl ─────────────────────────────────────────────────────────

test("manageUrl builds the management URL", () => {
  assert.equal(manageUrl(), `${API_URL}/manage/${CLIENT_ID}/`);
});

test("manageUrl appends an encoded next", () => {
  assert.equal(
    manageUrl({ next: "https://app.test.example/settings?tab=billing" }),
    `${API_URL}/manage/${CLIENT_ID}/?next=https%3A%2F%2Fapp.test.example%2Fsettings%3Ftab%3Dbilling`,
  );
});

test("manageUrl without UTA_CLIENT_ID throws UtaConfigError", () => {
  resetConfig();
  delete process.env.UTA_CLIENT_ID;
  configure({ redirect_uri: REDIRECT_URI, api_url: API_URL });
  assert.throws(() => manageUrl(), UtaConfigError);
});

// ── getAppInfo ────────────────────────────────────────────────────────

const APP_INFO_BODY = {
  client_id: CLIENT_ID,
  name: "Test App",
  tagline: "The best test app",
  listing_mode: "external",
  url: "https://app.test.example",
  marketplace_url: "https://www.usethatapp.com/apps/test-app/",
};

test("getAppInfo returns the app's public info", async () => {
  routes.appInfo = () => json(200, APP_INFO_BODY);
  const info = await getAppInfo();
  assert.equal(info.client_id, CLIENT_ID);
  assert.equal(info.name, "Test App");
  assert.equal(info.tagline, "The best test app");
  assert.equal(info.listing_mode, "external");
  assert.equal(info.url, "https://app.test.example");
  assert.equal(info.marketplace_url, "https://www.usethatapp.com/apps/test-app/");
  assert.deepEqual(info.raw, APP_INFO_BODY);
});

test("getAppInfo sends no Authorization header", async () => {
  routes.appInfo = () => json(200, APP_INFO_BODY);
  await getAppInfo();
  assert.equal(lastRequest.url, APP_INFO_URL);
  assert.equal(lastRequest.init.headers?.Authorization, undefined);
});

test("getAppInfo maps 404 to UtaError (not UtaServerError)", async () => {
  routes.appInfo = () => json(404, "not found");
  await assert.rejects(
    getAppInfo(),
    (e) => e instanceof UtaError && !(e instanceof UtaServerError) && /404/.test(e.message),
  );
});

for (const status of [429, 500, 503]) {
  test(`getAppInfo maps ${status} to UtaServerError`, async () => {
    routes.appInfo = () => json(status, "nope");
    await assert.rejects(getAppInfo(), UtaServerError);
  });
}

// ── getPrices ─────────────────────────────────────────────────────────

const PRICES_BODY = {
  client_id: CLIENT_ID,
  app_name: "Test App",
  has_free_tier: true,
  prices: [
    {
      public_id: "prc_month",
      product_id: "9c9e1c8e-0000-4000-8000-000000000001",
      product_name: "Pro",
      amount: "10.00",
      currency: "usd",
      is_recurring: true,
      frequency: "month",
      buy_url: `${API_URL}/buy/prc_month/`,
    },
    {
      public_id: "prc_once",
      product_id: "9c9e1c8e-0000-4000-8000-000000000002",
      product_name: "Lifetime",
      amount: "99.99",
      currency: "usd",
      is_recurring: false,
      frequency: null,
      buy_url: `${API_URL}/buy/prc_once/`,
    },
  ],
};

test("getPrices returns the app's price list", async () => {
  routes.prices = () => json(200, PRICES_BODY);
  const p = await getPrices();
  assert.equal(p.client_id, CLIENT_ID);
  assert.equal(p.app_name, "Test App");
  assert.equal(p.has_free_tier, true);
  assert.equal(p.prices.length, 2);
  const [monthly, oneTime] = p.prices;
  assert.equal(monthly.public_id, "prc_month");
  assert.equal(monthly.product_id, "9c9e1c8e-0000-4000-8000-000000000001");
  assert.equal(monthly.product_name, "Pro");
  assert.equal(monthly.amount, "10.00"); // decimal string, never a float
  assert.equal(monthly.currency, "usd");
  assert.equal(monthly.is_recurring, true);
  assert.equal(monthly.frequency, "month");
  assert.equal(monthly.buy_url, `${API_URL}/buy/prc_month/`);
  assert.equal(oneTime.is_recurring, false);
  assert.equal(oneTime.frequency, null);
  assert.deepEqual(p.raw, PRICES_BODY);
});

test("getPrices sends no Authorization header", async () => {
  routes.prices = () => json(200, PRICES_BODY);
  await getPrices();
  assert.equal(lastRequest.url, PRICES_URL);
  assert.equal(lastRequest.init.headers?.Authorization, undefined);
});

test("getPrices maps 404 to UtaError (not UtaServerError)", async () => {
  routes.prices = () => json(404, "not found");
  await assert.rejects(
    getPrices(),
    (e) => e instanceof UtaError && !(e instanceof UtaServerError) && /404/.test(e.message),
  );
});

for (const status of [429, 500, 503]) {
  test(`getPrices maps ${status} to UtaServerError`, async () => {
    routes.prices = () => json(status, "nope");
    await assert.rejects(getPrices(), UtaServerError);
  });
}
