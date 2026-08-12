/**
 * Framework-agnostic OIDC client functions.
 *
 * The whole public surface takes/returns primitives (strings + a
 * JSON-serializable `flowState`), so the SDK never touches your framework.
 * You wire three things yourself: read `code`/`state` off the callback
 * request, store/load `flowState` in your session, and issue the redirect.
 *
 *   const { authorizationUrl, flowState } = await beginLogin();
 *   const session = await completeLogin({ code, state, flowState });
 *   const ent = await getEntitlement(session.access_token);
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { jwtVerify } from "jose";

import {
  loadConfig,
  resolveApiUrl,
  resolveClientId,
  resolveRequestTimeoutSeconds,
  type UtaConfig,
} from "./config.js";
import { getJwks, getMetadata, type OidcMetadata } from "./discovery.js";
import {
  UtaAuthError,
  UtaError,
  UtaPermissionError,
  UtaServerError,
  UtaTokenError,
} from "./errors.js";
import { errMessage, fetchWithTimeout, type TimedResponse } from "./http.js";
import type { AppInfo, AppPrices, Entitlement, UtaFlowState, UtaPrice, UtaSession } from "./types.js";

const ENTITLEMENT_PATH = "/licensing/entitlement/";
const PUBLIC_APPS_PATH = "/api/v1/public/apps/";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function randomUrlSafe(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function s256Challenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// ──────────────────────────────────────────────────────────────────────
// Login: begin / complete
// ──────────────────────────────────────────────────────────────────────

export interface BeginLoginOptions {
  scopes?: string;
  redirectUri?: string;
  prompt?: string;
  extraParams?: Record<string, string>;
}

/**
 * Start an OIDC authorization-code (PKCE) login. Persist `flowState` in the
 * user's session, then redirect the browser to `authorizationUrl`. Pass the
 * same `flowState` back to {@link completeLogin} in your callback.
 */
export async function beginLogin(
  opts: BeginLoginOptions = {},
): Promise<{ authorizationUrl: string; flowState: UtaFlowState }> {
  const cfg = loadConfig();
  const meta = await getMetadata(cfg);

  const codeVerifier = randomUrlSafe();
  const state = randomUrlSafe();
  const nonce = randomUrlSafe();
  const redirectUri = opts.redirectUri ?? cfg.redirect_uri;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.client_id,
    redirect_uri: redirectUri,
    scope: opts.scopes ?? cfg.scopes,
    state,
    nonce,
    code_challenge: s256Challenge(codeVerifier),
    code_challenge_method: "S256",
  });
  if (opts.prompt) params.set("prompt", opts.prompt);
  for (const [k, v] of Object.entries(opts.extraParams ?? {})) {
    // Silently overwriting state/nonce/code_challenge/... would break the
    // CSRF, replay, and PKCE protections recorded in flowState.
    if (params.has(k)) {
      throw new UtaError(`extraParams may not override reserved parameter '${k}'`);
    }
    params.set(k, v);
  }

  return {
    authorizationUrl: meta.authorization_endpoint + "?" + params.toString(),
    flowState: { state, nonce, codeVerifier, redirectUri },
  };
}

export interface CompleteLoginArgs {
  code: string | null | undefined;
  state: string | null | undefined;
  flowState: UtaFlowState;
}

/**
 * Finish login: validate `state`, exchange `code`, verify the ID token
 * (signature via JWKS, `iss`/`aud`/`exp`/`nonce`). Returns a session whose
 * `sub` is the user's stable per-app id.
 */
export async function completeLogin(args: CompleteLoginArgs): Promise<UtaSession> {
  const cfg = loadConfig();
  const { code, state, flowState } = args;
  if (!code) throw new UtaAuthError("missing authorization code");
  if (!flowState?.state || !timingSafeEqualStr(String(state ?? ""), flowState.state)) {
    throw new UtaAuthError("state mismatch — possible CSRF or a stale login");
  }
  // Fail loudly if the session layer dropped fields — a missing nonce would
  // otherwise silently disable replay protection.
  if (!flowState.nonce || !flowState.codeVerifier) {
    throw new UtaAuthError(
      "flowState is missing nonce/codeVerifier — was it stored and restored intact?",
    );
  }

  const meta = await getMetadata(cfg);
  const token = await tokenRequest(cfg, meta, {
    grant_type: "authorization_code",
    code,
    redirect_uri: flowState.redirectUri ?? cfg.redirect_uri,
    code_verifier: flowState.codeVerifier,
  });

  const idToken = token.id_token;
  if (typeof idToken !== "string") {
    throw new UtaTokenError("token response did not include an id_token");
  }
  const claims = await validateIdToken(cfg, meta, idToken, flowState.nonce);
  return sessionFromToken(token, String(claims.sub), claims, idToken);
}

// ──────────────────────────────────────────────────────────────────────
// Refresh / userinfo / logout
// ──────────────────────────────────────────────────────────────────────

/**
 * Exchange a refresh token for a fresh session. usethatapp.com rotates
 * refresh tokens, so use the returned `refresh_token` next time. If the
 * provider omits an ID token, `sub` is resolved via the userinfo endpoint.
 */
export async function refresh(refreshToken: string): Promise<UtaSession> {
  const cfg = loadConfig();
  if (!refreshToken) throw new UtaTokenError("refresh_token is required");
  const meta = await getMetadata(cfg);
  const token = await tokenRequest(cfg, meta, {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    scope: cfg.scopes,
  });
  // Carry the old refresh token forward if rotation didn't return a new one.
  if (typeof token.refresh_token !== "string") token.refresh_token = refreshToken;

  const idToken = token.id_token;
  if (typeof idToken === "string") {
    const claims = await validateIdToken(cfg, meta, idToken, null);
    return sessionFromToken(token, String(claims.sub), claims, idToken);
  }
  const info = await userinfo(String(token.access_token));
  if (typeof info.sub !== "string" || !info.sub) {
    throw new UtaTokenError("userinfo response missing sub");
  }
  return sessionFromToken(token, info.sub, info, null);
}

/** Fetch the OIDC userinfo claims (`sub` only — no PII). */
export async function userinfo(accessToken: string): Promise<Record<string, unknown>> {
  const cfg = loadConfig();
  const meta = await getMetadata(cfg);
  if (!meta.userinfo_endpoint) throw new UtaError("provider has no userinfo_endpoint");
  let resp: TimedResponse;
  try {
    resp = await fetchWithTimeout(
      meta.userinfo_endpoint,
      { headers: { Authorization: `Bearer ${accessToken}` } },
      cfg.request_timeout_seconds,
    );
  } catch (e) {
    throw new UtaServerError(`network error calling userinfo: ${errMessage(e)}`);
  }
  if (resp.status === 401) throw new UtaTokenError(`401 from userinfo: ${resp.text}`);
  if (resp.status === 403) throw new UtaPermissionError(`403 from userinfo: ${resp.text}`);
  if (resp.status >= 500) throw new UtaServerError(`${resp.status} from userinfo`);
  if (!resp.ok) throw new UtaError(`unexpected status ${resp.status} from userinfo: ${resp.text}`);
  try {
    return JSON.parse(resp.text) as Record<string, unknown>;
  } catch (e) {
    throw new UtaError(`userinfo response is not valid JSON: ${errMessage(e)}`);
  }
}

export interface LogoutUrlOptions {
  idToken?: string | null;
  postLogoutRedirectUri?: string;
  state?: string;
}

/** Build the RP-initiated end-session (logout) URL to redirect to. */
export async function logoutUrl(opts: LogoutUrlOptions = {}): Promise<string> {
  const cfg = loadConfig();
  const meta = await getMetadata(cfg);
  const endpoint = meta.end_session_endpoint;
  if (!endpoint) throw new UtaError("provider has no end_session_endpoint");
  const params = new URLSearchParams();
  if (opts.idToken) params.set("id_token_hint", opts.idToken);
  if (opts.postLogoutRedirectUri) {
    params.set("post_logout_redirect_uri", opts.postLogoutRedirectUri);
    params.set("client_id", cfg.client_id);
  }
  if (opts.state) params.set("state", opts.state);
  const qs = params.toString();
  if (!qs) return endpoint;
  return `${endpoint}${endpoint.includes("?") ? "&" : "?"}${qs}`;
}

// ──────────────────────────────────────────────────────────────────────
// Entitlement (the OAuth-era replacement for getVersion)
// ──────────────────────────────────────────────────────────────────────

export interface GetEntitlementOptions {
  /** Override the per-request timeout (seconds). */
  timeoutSeconds?: number;
}

/**
 * Query the user's live license state for your app. Sends
 * `Authorization: Bearer <accessToken>` to `/licensing/entitlement/`.
 * Always authoritative — a canceled license stops being entitled
 * immediately, regardless of token lifetime.
 */
export async function getEntitlement(
  accessToken: string,
  opts: GetEntitlementOptions = {},
): Promise<Entitlement> {
  const cfg = loadConfig();
  if (!accessToken) throw new UtaTokenError("accessToken must be a non-empty string");
  const data = await apiGetJson(
    cfg.api_url + ENTITLEMENT_PATH,
    "entitlement",
    opts.timeoutSeconds ?? cfg.request_timeout_seconds,
    { Authorization: `Bearer ${accessToken}` },
    raiseForEntitlementStatus,
  );
  return parseEntitlement(data);
}

// ──────────────────────────────────────────────────────────────────────
// Purchase links & public pricing (selling from your own website)
// ──────────────────────────────────────────────────────────────────────

export interface PurchaseUrlOptions {
  /** Where the buyer lands after purchase. Must be an HTTPS URL on your
   * app's registered domain — validated server-side; invalid values show
   * the buyer a "misconfigured link" page. Defaults to your app's
   * registered Login URL. */
  next?: string;
  /** Affiliate code to credit for the sale. */
  ref?: string;
  /** Prefills the buyer's email on the checkout page. */
  email?: string;
}

/**
 * Build the hosted purchase (checkout) URL for one of your app's prices.
 * Pure URL builder — no network. `priceId` is the opaque public price
 * identifier (`prc_…`) from {@link getPrices} — or just use each price's
 * ready-made `buy_url` directly.
 *
 * Uses config only for the API URL. Being pure, the logic is trivially
 * copyable into browser code even though this package is Node-only.
 */
export function purchaseUrl(priceId: string, opts: PurchaseUrlOptions = {}): string {
  if (!priceId || !priceId.trim()) {
    throw new UtaError("priceId must be a non-empty string");
  }
  const params = new URLSearchParams();
  if (opts.next) params.set("next", opts.next);
  if (opts.ref) params.set("ref", opts.ref);
  if (opts.email) params.set("email", opts.email);
  const url = `${resolveApiUrl()}/buy/${encodeURIComponent(priceId)}/`;
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

export interface ManageUrlOptions {
  /** Becomes the "Back to app" link on the management page. */
  next?: string;
}

/**
 * Build the URL of the buyer's subscription-management page scoped to this
 * app. Pure URL builder — no network. Requires `UTA_CLIENT_ID`.
 */
export function manageUrl(opts: ManageUrlOptions = {}): string {
  const url = `${resolveApiUrl()}/manage/${encodeURIComponent(resolveClientId())}/`;
  if (!opts.next) return url;
  return `${url}?${new URLSearchParams({ next: opts.next }).toString()}`;
}

export interface GetAppInfoOptions {
  /** Override the per-request timeout (seconds). */
  timeoutSeconds?: number;
}

/**
 * Fetch your app's public listing info (name, tagline, listing mode, URLs).
 * Anonymous — no Authorization header is sent, so no login is needed.
 */
export async function getAppInfo(opts: GetAppInfoOptions = {}): Promise<AppInfo> {
  const url = resolveApiUrl() + PUBLIC_APPS_PATH + encodeURIComponent(resolveClientId()) + "/";
  const data = await publicApiGet(url, "app info", opts.timeoutSeconds ?? resolveRequestTimeoutSeconds());
  return parseAppInfo(data);
}

export interface GetPricesOptions {
  /** Override the per-request timeout (seconds). */
  timeoutSeconds?: number;
}

/**
 * Fetch your app's public price list. Anonymous — no Authorization header
 * is sent, so no login is needed. Render your pricing from this API instead
 * of hardcoding amounts. Each price's `product_id` is the opaque `prod_…`
 * identifier to gate on — compare it against
 * {@link Entitlement.product_public_id} (`Entitlement.product_id` still
 * carries the legacy UUID until the platform's identifier cutover). Each
 * `buy_url` is the ready-made hosted checkout link.
 */
export async function getPrices(opts: GetPricesOptions = {}): Promise<AppPrices> {
  const url = resolveApiUrl() + PUBLIC_APPS_PATH + encodeURIComponent(resolveClientId()) + "/prices/";
  const data = await publicApiGet(url, "prices", opts.timeoutSeconds ?? resolveRequestTimeoutSeconds());
  return parsePrices(data);
}

// ──────────────────────────────────────────────────────────────────────
// Internals
// ──────────────────────────────────────────────────────────────────────

async function tokenRequest(
  cfg: UtaConfig,
  meta: OidcMetadata,
  data: Record<string, string>,
): Promise<Record<string, unknown>> {
  const body = new URLSearchParams(data);
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  // Confidential clients use HTTP Basic (client_secret_basic); public
  // clients send client_id in the body and rely on PKCE.
  if (cfg.client_secret) {
    headers.Authorization =
      "Basic " + Buffer.from(`${cfg.client_id}:${cfg.client_secret}`).toString("base64");
  } else {
    body.set("client_id", cfg.client_id);
  }

  let resp: TimedResponse;
  try {
    resp = await fetchWithTimeout(
      meta.token_endpoint,
      { method: "POST", headers, body: body.toString() },
      cfg.request_timeout_seconds,
    );
  } catch (e) {
    throw new UtaServerError(`network error calling token endpoint: ${errMessage(e)}`);
  }
  const text = resp.text;
  if (resp.status >= 500) {
    throw new UtaServerError(`${resp.status} from token endpoint: ${text}`);
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new UtaTokenError(
      `token endpoint returned non-JSON (${resp.status}): ${text.slice(0, 200)}`,
    );
  }
  if (resp.status !== 200 || "error" in payload) {
    const err = (payload.error as string) ?? `http_${resp.status}`;
    const desc = (payload.error_description as string) ?? "";
    throw new UtaTokenError(`token endpoint error: ${err} ${desc}`.trim());
  }
  if (typeof payload.access_token !== "string") {
    throw new UtaTokenError("token response missing access_token");
  }
  return payload;
}

async function validateIdToken(
  cfg: UtaConfig,
  meta: OidcMetadata,
  idToken: string,
  nonce: string | null,
): Promise<Record<string, unknown>> {
  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(idToken, getJwks(meta), {
      issuer: meta.issuer,
      audience: cfg.client_id,
      clockTolerance: cfg.clock_skew_seconds,
      algorithms: ["RS256"],
    });
    payload = result.payload as Record<string, unknown>;
  } catch (e) {
    throw new UtaTokenError(`ID token validation failed: ${errMessage(e)}`);
  }
  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new UtaTokenError("ID token missing sub");
  }
  // `null` means the caller legitimately expects no nonce (refresh grant);
  // anything else — including a missing/undefined value — must match exactly.
  if (nonce !== null && payload.nonce !== nonce) {
    throw new UtaTokenError("ID token nonce mismatch");
  }
  return payload;
}

function sessionFromToken(
  token: Record<string, unknown>,
  sub: string,
  claims: Record<string, unknown>,
  idToken: string | null,
): UtaSession {
  const expiresIn = Number(token.expires_in ?? 0) || 0;
  return {
    sub,
    access_token: String(token.access_token),
    expires_at: nowSeconds() + expiresIn,
    refresh_token: typeof token.refresh_token === "string" ? token.refresh_token : null,
    id_token: idToken,
    scope: typeof token.scope === "string" ? token.scope : "",
    token_type: typeof token.token_type === "string" ? token.token_type : "Bearer",
    claims,
  };
}

function raiseForEntitlementStatus(status: number, bodyText: string): void {
  if (status >= 200 && status < 300) return;
  if (status === 400) {
    throw new UtaError(`400 from entitlement (client not linked to an app?): ${bodyText}`);
  }
  if (status === 401) {
    throw new UtaTokenError(`401 from entitlement — access token invalid/expired: ${bodyText}`);
  }
  if (status === 403) {
    throw new UtaPermissionError(`403 from entitlement — missing 'entitlements' scope: ${bodyText}`);
  }
  if (status === 429) {
    throw new UtaServerError(`429 from entitlement — rate limited, retry with backoff: ${bodyText}`);
  }
  if (status >= 500 && status < 600) {
    throw new UtaServerError(`${status} from entitlement: ${bodyText}`);
  }
  throw new UtaError(`unexpected status ${status} from entitlement: ${bodyText}`);
}

function parseEntitlement(obj: Record<string, unknown>): Entitlement {
  return {
    entitled: Boolean(obj.entitled),
    version: typeof obj.version === "string" ? obj.version : null,
    product_id: typeof obj.product_id === "string" ? obj.product_id : null,
    product_public_id:
      typeof obj.product_public_id === "string" ? obj.product_public_id : null,
    status: typeof obj.status === "string" ? obj.status : "none",
    is_free: Boolean(obj.is_free),
    period_end: typeof obj.period_end === "string" ? obj.period_end : null,
    raw: obj,
  };
}

/** GET `url`, raise typed errors per `raiseForStatus`, decode the JSON object. */
async function apiGetJson(
  url: string,
  what: string,
  timeoutSeconds: number,
  headers: Record<string, string>,
  raiseForStatus: (status: number, bodyText: string) => void,
): Promise<Record<string, unknown>> {
  let resp: TimedResponse;
  try {
    resp = await fetchWithTimeout(url, { headers }, timeoutSeconds);
  } catch (e) {
    throw new UtaServerError(`network error calling ${what}: ${errMessage(e)}`);
  }
  raiseForStatus(resp.status, resp.text);
  let data: unknown;
  try {
    data = JSON.parse(resp.text);
  } catch (e) {
    throw new UtaError(`${what} response is not valid JSON: ${errMessage(e)}`);
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new UtaError(`${what} response is not a JSON object`);
  }
  return data as Record<string, unknown>;
}

/** Anonymous GET against the public API; returns the decoded JSON object. */
function publicApiGet(
  url: string,
  what: string,
  timeoutSeconds: number,
): Promise<Record<string, unknown>> {
  return apiGetJson(url, what, timeoutSeconds, {}, (status, bodyText) =>
    raiseForPublicApiStatus(status, what, bodyText),
  );
}

function raiseForPublicApiStatus(status: number, what: string, bodyText: string): void {
  if (status >= 200 && status < 300) return;
  if (status === 404) {
    throw new UtaError(
      `404 from ${what} — app unknown, unpublished, or external sales not enabled: ${bodyText}`,
    );
  }
  if (status === 429) {
    throw new UtaServerError(`429 from ${what} — rate limited, retry with backoff: ${bodyText}`);
  }
  if (status >= 500 && status < 600) {
    throw new UtaServerError(`${status} from ${what}: ${bodyText}`);
  }
  throw new UtaError(`unexpected status ${status} from ${what}: ${bodyText}`);
}

function parseAppInfo(obj: Record<string, unknown>): AppInfo {
  return {
    client_id: typeof obj.client_id === "string" ? obj.client_id : "",
    name: typeof obj.name === "string" ? obj.name : "",
    tagline: typeof obj.tagline === "string" ? obj.tagline : "",
    listing_mode: typeof obj.listing_mode === "string" ? obj.listing_mode : "",
    url: typeof obj.url === "string" ? obj.url : "",
    marketplace_url: typeof obj.marketplace_url === "string" ? obj.marketplace_url : "",
    raw: obj,
  };
}

function parsePrice(data: unknown): UtaPrice {
  const obj =
    data !== null && typeof data === "object" && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : {};
  return {
    public_id: typeof obj.public_id === "string" ? obj.public_id : "",
    product_id: typeof obj.product_id === "string" ? obj.product_id : "",
    product_name: typeof obj.product_name === "string" ? obj.product_name : "",
    amount: typeof obj.amount === "string" ? obj.amount : "",
    currency: typeof obj.currency === "string" ? obj.currency : "",
    is_recurring: Boolean(obj.is_recurring),
    frequency: typeof obj.frequency === "string" ? obj.frequency : null,
    buy_url: typeof obj.buy_url === "string" ? obj.buy_url : "",
  };
}

function parsePrices(obj: Record<string, unknown>): AppPrices {
  return {
    client_id: typeof obj.client_id === "string" ? obj.client_id : "",
    app_name: typeof obj.app_name === "string" ? obj.app_name : "",
    has_free_tier: Boolean(obj.has_free_tier),
    prices: Array.isArray(obj.prices) ? obj.prices.map(parsePrice) : [],
    raw: obj,
  };
}
