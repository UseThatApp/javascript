import { constants, randomBytes, sign } from "node:crypto";

import { loadConfig, type UtaConfig } from "./config.js";
import {
  UtaAppMismatchError,
  UtaBadRequestError,
  UtaError,
  UtaPayloadExpiredError,
  UtaServerError,
  UtaSessionRevokedError,
  UtaSignatureError,
  UtaUnknownSessionError,
} from "./errors.js";
import { unpackPayload, type InnerPayload } from "./payloads.js";
import type { UtaUser } from "./types.js";

const GETVERSION_PATH = "/licensing/getversion/";

// Process-local TTL cache: { user_key: { version, expires_at_unix_seconds } }
type CacheEntry = { version: string | null; expires_at: number };
const versionCache: Map<string, CacheEntry> = new Map();

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ──────────────────────────────────────────────────────────────────────
// getUserFromRequest
// ──────────────────────────────────────────────────────────────────────

function buildUser(
  inner: InnerPayload,
  expectedAppId: string,
  clockSkew: number,
): UtaUser {
  for (const field of ["kind", "user_key", "app_id", "iat", "exp", "nonce"] as const) {
    if (!(field in inner)) {
      throw new UtaError(`decrypted payload missing field: ${field}`);
    }
  }

  if (inner.kind !== "launch") {
    throw new UtaError(`unexpected payload kind: ${JSON.stringify(inner.kind)}`);
  }

  if (typeof inner.app_id !== "string" || inner.app_id !== expectedAppId) {
    throw new UtaAppMismatchError(
      "payload app_id does not match configured UTA_APP_ID",
    );
  }

  if (
    typeof inner.iat !== "number" ||
    typeof inner.exp !== "number" ||
    !Number.isFinite(inner.iat) ||
    !Number.isFinite(inner.exp)
  ) {
    throw new UtaError("payload iat/exp are not integers");
  }
  const iat = Math.trunc(inner.iat);
  const exp = Math.trunc(inner.exp);

  if (nowSeconds() > exp + clockSkew) {
    throw new UtaPayloadExpiredError("launch payload has expired");
  }

  if (typeof inner.user_key !== "string" || inner.user_key === "") {
    throw new UtaError("payload user_key must be a non-empty string");
  }

  const versionHint = inner.version_hint;
  if (versionHint !== undefined && versionHint !== null && typeof versionHint !== "string") {
    throw new UtaError("payload version_hint must be a string when present");
  }

  return {
    user_key: inner.user_key,
    app_id: inner.app_id,
    issued_at: iat,
    expires_at: exp,
    version_hint: typeof versionHint === "string" ? versionHint : null,
  };
}

/** Verify + decrypt a raw launch envelope (string or already-parsed object). */
export function getUser(
  payload: string | Record<string, unknown>,
): UtaUser {
  const cfg = loadConfig();
  const inner = unpackPayload(payload, {
    developerPrivateKey: cfg.private_key,
    marketPublicKey: cfg.market_public_key,
  });
  return buildUser(inner, cfg.app_id, cfg.clock_skew_seconds);
}

/** Minimal shape of an Express/Connect-style request. */
export interface UtaRequestLike {
  body?: unknown;
}

function extractPayloadFromRequest(req: UtaRequestLike): string | Record<string, unknown> {
  const body = req?.body;
  if (body == null || typeof body !== "object") {
    throw new UtaError("could not find 'uta_payload' in request body");
  }
  const val = (body as Record<string, unknown>).uta_payload;
  if (val == null) {
    throw new UtaError("could not find 'uta_payload' in request body");
  }
  if (typeof val !== "string" && (typeof val !== "object" || Array.isArray(val))) {
    throw new UtaError("'uta_payload' must be a string or object");
  }
  return val as string | Record<string, unknown>;
}

/**
 * Verify the launch envelope on an Express/Connect-style inbound request.
 * Expects body-parser middleware to have populated `req.body` already.
 */
export function getUserFromRequest(req: UtaRequestLike): UtaUser {
  const payload = extractPayloadFromRequest(req);
  return getUser(payload);
}

// ──────────────────────────────────────────────────────────────────────
// getVersion
// ──────────────────────────────────────────────────────────────────────

interface GetVersionBody extends Record<string, unknown> {
  app_id: string;
  user_key: string;
  ts: number;
  nonce: string;
  signature?: string;
}

/**
 * Build a canonical JSON string matching Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))` — sorted keys,
 * compact separators, UTF-8. Only flat objects with string/number values
 * are signed here, so a shallow sort is sufficient.
 */
function canonicalize(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  return JSON.stringify(obj, keys);
}

function buildGetVersionBody(cfg: UtaConfig, userKey: string): GetVersionBody {
  const body: GetVersionBody = {
    app_id: cfg.app_id,
    user_key: userKey,
    ts: nowSeconds(),
    nonce: randomBytes(16).toString("hex"),
  };
  const canonical = Buffer.from(canonicalize(body), "utf8");
  const signature = sign("sha256", canonical, {
    key: cfg.private_key,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
  });
  body.signature = signature.toString("hex");
  return body;
}

function cacheGet(userKey: string): CacheEntry | null {
  const entry = versionCache.get(userKey);
  if (entry === undefined) return null;
  if (nowSeconds() >= entry.expires_at) {
    versionCache.delete(userKey);
    return null;
  }
  return entry;
}

function cachePut(userKey: string, version: string | null, cacheUntil: number): void {
  versionCache.set(userKey, { version, expires_at: cacheUntil });
}

/** Drop all entries from the process-local version cache. */
export function clearVersionCache(): void {
  versionCache.clear();
}

function handleResponseStatus(status: number, bodyText: string): void {
  if (status >= 200 && status < 300) return;
  if (status === 400) {
    throw new UtaBadRequestError(`400 from getversion: ${bodyText}`);
  }
  if (status === 401) {
    throw new UtaSignatureError(`401 from getversion: ${bodyText}`);
  }
  if (status === 403) {
    throw new UtaSessionRevokedError(`403 from getversion: ${bodyText}`);
  }
  if (status === 404) {
    throw new UtaUnknownSessionError(`404 from getversion: ${bodyText}`);
  }
  if (status >= 500 && status < 600) {
    throw new UtaServerError(`${status} from getversion: ${bodyText}`);
  }
  throw new UtaError(`unexpected status ${status} from getversion: ${bodyText}`);
}

function parseGetVersionResponse(data: unknown): { version: string | null; cacheUntil: number } {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new UtaError("getversion response is not a JSON object");
  }
  const obj = data as Record<string, unknown>;
  if (!("version" in obj)) {
    throw new UtaError("getversion response missing 'version'");
  }
  const version = obj.version;
  if (version !== null && typeof version !== "string") {
    throw new UtaError("getversion response 'version' must be string or null");
  }

  let cacheUntil: number;
  const rawCacheUntil = obj.cache_until;
  if (typeof rawCacheUntil === "number" && Number.isFinite(rawCacheUntil)) {
    cacheUntil = Math.trunc(rawCacheUntil);
  } else {
    const rawCacheSeconds = obj.cache_seconds;
    if (typeof rawCacheSeconds === "number" && Number.isFinite(rawCacheSeconds)) {
      cacheUntil = nowSeconds() + Math.trunc(rawCacheSeconds);
    } else {
      cacheUntil = nowSeconds(); // don't cache
    }
  }
  return { version, cacheUntil };
}

export interface GetVersionOptions {
  /** When false, bypass the process-local TTL cache (default: true). */
  useCache?: boolean;
}

/**
 * Fetch the current license tier for `userKey` from the marketplace.
 *
 * Returns the product/version name as a string, or `null` if the user
 * has no active license.
 *
 * Throws `UtaBadRequestError`, `UtaSignatureError`, `UtaSessionRevokedError`,
 * `UtaUnknownSessionError`, `UtaServerError`, or `UtaError` on transport
 * or schema failures.
 */
export async function getVersion(
  userKey: string,
  opts: GetVersionOptions = {},
): Promise<string | null> {
  if (typeof userKey !== "string" || userKey === "") {
    throw new UtaError("userKey must be a non-empty string");
  }
  const useCache = opts.useCache !== false;

  const cfg = loadConfig();

  if (useCache) {
    const cached = cacheGet(userKey);
    if (cached !== null) {
      return cached.version;
    }
  }

  const body = buildGetVersionBody(cfg, userKey);
  const url = cfg.api_url + GETVERSION_PATH;

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    cfg.request_timeout_seconds * 1000,
  );

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "follow",
    });
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaServerError(`network error calling getversion: ${err}`);
  } finally {
    clearTimeout(timer);
  }

  const bodyText = await response.text();
  handleResponseStatus(response.status, bodyText);

  let data: unknown;
  try {
    data = JSON.parse(bodyText);
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaError(`getversion response is not valid JSON: ${err}`);
  }

  const { version, cacheUntil } = parseGetVersionResponse(data);
  if (useCache && cacheUntil > nowSeconds()) {
    cachePut(userKey, version, cacheUntil);
  }
  return version;
}
