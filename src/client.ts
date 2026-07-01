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

import { loadConfig, type UtaConfig } from "./config.js";
import { getJwks, getMetadata, type OidcMetadata } from "./discovery.js";
import {
  UtaAuthError,
  UtaError,
  UtaPermissionError,
  UtaServerError,
  UtaTokenError,
} from "./errors.js";
import { errMessage, fetchWithTimeout } from "./http.js";
import type { Entitlement, UtaFlowState, UtaSession } from "./types.js";

const ENTITLEMENT_PATH = "/licensing/entitlement/";

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
  for (const [k, v] of Object.entries(opts.extraParams ?? {})) params.set(k, v);

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
  return sessionFromToken(token, String(info.sub ?? ""), info, null);
}

/** Fetch the OIDC userinfo claims (`sub` only — no PII). */
export async function userinfo(accessToken: string): Promise<Record<string, unknown>> {
  const cfg = loadConfig();
  const meta = await getMetadata(cfg);
  if (!meta.userinfo_endpoint) throw new UtaError("provider has no userinfo_endpoint");
  let resp: Response;
  try {
    resp = await fetchWithTimeout(
      meta.userinfo_endpoint,
      { headers: { Authorization: `Bearer ${accessToken}` } },
      cfg.request_timeout_seconds,
    );
  } catch (e) {
    throw new UtaServerError(`network error calling userinfo: ${errMessage(e)}`);
  }
  if (resp.status === 401) throw new UtaTokenError(`401 from userinfo: ${await resp.text()}`);
  if (resp.status >= 500) throw new UtaServerError(`${resp.status} from userinfo`);
  try {
    return (await resp.json()) as Record<string, unknown>;
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
  const url = cfg.api_url + ENTITLEMENT_PATH;
  let resp: Response;
  try {
    resp = await fetchWithTimeout(
      url,
      { headers: { Authorization: `Bearer ${accessToken}` } },
      opts.timeoutSeconds ?? cfg.request_timeout_seconds,
    );
  } catch (e) {
    throw new UtaServerError(`network error calling entitlement: ${errMessage(e)}`);
  }
  const text = await resp.text();
  raiseForEntitlementStatus(resp.status, text);
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new UtaError(`entitlement response is not valid JSON: ${errMessage(e)}`);
  }
  return parseEntitlement(data);
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

  let resp: Response;
  try {
    resp = await fetchWithTimeout(
      meta.token_endpoint,
      { method: "POST", headers, body: body.toString() },
      cfg.request_timeout_seconds,
    );
  } catch (e) {
    throw new UtaServerError(`network error calling token endpoint: ${errMessage(e)}`);
  }
  const text = await resp.text();
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
  if (nonce != null && payload.nonce !== nonce) {
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
  if (status >= 500 && status < 600) {
    throw new UtaServerError(`${status} from entitlement: ${bodyText}`);
  }
  throw new UtaError(`unexpected status ${status} from entitlement: ${bodyText}`);
}

function parseEntitlement(data: unknown): Entitlement {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new UtaError("entitlement response is not a JSON object");
  }
  const obj = data as Record<string, unknown>;
  return {
    entitled: Boolean(obj.entitled),
    version: typeof obj.version === "string" ? obj.version : null,
    product_id: typeof obj.product_id === "string" ? obj.product_id : null,
    status: typeof obj.status === "string" ? obj.status : "none",
    is_free: Boolean(obj.is_free),
    period_end: typeof obj.period_end === "string" ? obj.period_end : null,
    raw: obj,
  };
}
