import { readFileSync } from "node:fs";

import { UtaConfigError } from "./errors.js";

/** Production defaults. usethatapp.com only serves the `www` host. */
export const DEFAULT_ISSUER = "https://www.usethatapp.com/o";
export const DEFAULT_API_URL = "https://www.usethatapp.com";
export const DEFAULT_SCOPES = "openid entitlements";

export interface UtaConfig {
  readonly client_id: string;
  readonly redirect_uri: string;
  readonly issuer: string;
  readonly api_url: string;
  readonly scopes: string;
  /** `undefined` for a public (browser/native) PKCE client. */
  readonly client_secret: string | undefined;
  readonly request_timeout_seconds: number;
  readonly clock_skew_seconds: number;
}

export interface UtaConfigOverrides {
  client_id?: string;
  client_secret?: string;
  client_secret_path?: string;
  redirect_uri?: string;
  issuer?: string;
  api_url?: string;
  scopes?: string;
  request_timeout_seconds?: number;
  clock_skew_seconds?: number;
}

let _cached: UtaConfig | null = null;
let _overrides: UtaConfigOverrides = {};

function readRaw(name: string): unknown {
  const overrideKey = name.toLowerCase().replace(/^uta_/, "") as keyof UtaConfigOverrides;
  const override = _overrides[overrideKey];
  if (override !== undefined) {
    return override;
  }
  const env = process.env[name];
  return env === undefined ? undefined : env;
}

function readStr(name: string): string | undefined {
  const raw = readRaw(name);
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") {
    throw new UtaConfigError(`${name} must be a string`);
  }
  return raw;
}

/**
 * Resolve a secret from `UTA_FOO` or by reading the file at `UTA_FOO_PATH`.
 * The `*_PATH` variant supports hosting providers that mount secret files
 * (Render Secret Files, Fly volumes, k8s secret volumes, …).
 *
 * Precedence is decided per LAYER (configure() overrides, then the
 * environment), not per key: `configure({client_secret_path})` must
 * outrank an env `UTA_CLIENT_SECRET`, or the developer's just-configured
 * secret file silently loses to a stale deploy-env secret (the Python
 * SDK review's finding 2 — the same bug existed here). Within a layer
 * the direct value wins; an empty direct value counts as unset, so a
 * blank var can't shadow a mounted secret file.
 */
function readSecretOrPath(directName: string, pathName: string): string | undefined {
  const layers: Array<(name: string) => string | undefined> = [
    (name) => {
      const key = name.toLowerCase().replace(/^uta_/, "") as keyof UtaConfigOverrides;
      const v = _overrides[key];
      if (v === undefined) return undefined;
      if (typeof v !== "string") throw new UtaConfigError(`${name} must be a string`);
      return v;
    },
    (name) => process.env[name],
  ];
  for (const layer of layers) {
    const direct = layer(directName);
    if (direct) return direct;
    const path = layer(pathName);
    if (path === undefined || path === "") continue;
    try {
      return readFileSync(path, "utf8").trim();
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      throw new UtaConfigError(`${pathName}=${path}: could not read file: ${err}`);
    }
  }
  return undefined;
}

function readInt(name: string, fallback: number, min: number): number {
  const raw = readRaw(name);
  if (raw === undefined) return fallback;
  let n: number;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    n = Math.trunc(raw);
  } else if (typeof raw === "string") {
    const trimmed = raw.trim();
    n = parseInt(trimmed, 10);
    if (Number.isNaN(n) || String(n) !== trimmed) {
      throw new UtaConfigError(`${name} must be an integer`);
    }
  } else {
    throw new UtaConfigError(`${name} must be an integer`);
  }
  if (n < min) {
    throw new UtaConfigError(`${name} must be an integer >= ${min}`);
  }
  return n;
}

// Derived from UtaConfigOverrides via `satisfies`, so adding an option
// to the interface without listing it here is a COMPILE error — the typo
// guard must not itself drift into rejecting valid options (review
// finding 7).
const OVERRIDE_KEYS = {
  client_id: true,
  client_secret: true,
  client_secret_path: true,
  redirect_uri: true,
  issuer: true,
  api_url: true,
  scopes: true,
  request_timeout_seconds: true,
  clock_skew_seconds: true,
} as const satisfies Record<keyof UtaConfigOverrides, true>;

const ALLOWED_OVERRIDES = new Set<string>(Object.keys(OVERRIDE_KEYS));

/**
 * Override one or more settings at runtime (useful for tests or apps that
 * prefer programmatic configuration over env vars). Clears the cached config.
 *
 * Unknown option names throw {@link UtaConfigError}, matching the Python
 * SDK: TypeScript's excess-property check only guards object literals, so
 * without this a typo from plain JavaScript (or a config object assembled
 * elsewhere) was silently ignored — and the setting it was meant to change
 * kept its default, e.g. api_url pointing at production (Quiver J-08).
 */
export function configure(overrides: UtaConfigOverrides): void {
  const unknown = Object.keys(overrides).filter((k) => !ALLOWED_OVERRIDES.has(k));
  if (unknown.length > 0) {
    throw new UtaConfigError(`unknown configure() option(s): ${unknown.sort().join(", ")}`);
  }
  _overrides = { ..._overrides, ...overrides };
  _cached = null;
}

/** Drop the cached config and all programmatic overrides. */
export function resetConfig(): void {
  _cached = null;
  _overrides = {};
}

// ── Partial resolvers for the purchase/pricing surface ─────────────────
// purchaseUrl/manageUrl/getAppInfo/getPrices need only a slice of the
// config, and a pricing-only integration (e.g. a marketing page) has no
// reason to configure OIDC settings like UTA_REDIRECT_URI. These read the
// same overrides/env as loadConfig without demanding the full OIDC set —
// matching the Python SDK's resolve_* helpers.

/** The marketplace base URL (`UTA_API_URL`, default production). */
export function resolveApiUrl(): string {
  return (readStr("UTA_API_URL") ?? DEFAULT_API_URL).replace(/\/+$/, "");
}

/** The app's public OAuth client id (`UTA_CLIENT_ID`, required). */
export function resolveClientId(): string {
  const clientId = readStr("UTA_CLIENT_ID");
  if (!clientId) {
    throw new UtaConfigError("UTA_CLIENT_ID is required");
  }
  return clientId;
}

/**
 * The app's OAuth client secret (`UTA_CLIENT_SECRET` /
 * `UTA_CLIENT_SECRET_PATH`), required — the License Key API is
 * server-side only and authenticates with client credentials.
 */
export function resolveClientSecret(): string {
  const secret = readSecretOrPath("UTA_CLIENT_SECRET", "UTA_CLIENT_SECRET_PATH");
  if (!secret) {
    throw new UtaConfigError(
      "UTA_CLIENT_SECRET is required for the License Key API " +
        "(server-side calls authenticate with your app's client credentials)",
    );
  }
  return secret;
}

/** Per-request timeout in seconds (`UTA_REQUEST_TIMEOUT_SECONDS`, default 10). */
export function resolveRequestTimeoutSeconds(): number {
  return readInt("UTA_REQUEST_TIMEOUT_SECONDS", 10, 1);
}

/** Resolve and cache SDK configuration. */
export function loadConfig(force = false): UtaConfig {
  if (_cached !== null && !force) {
    return _cached;
  }

  const client_id = readStr("UTA_CLIENT_ID");
  if (!client_id) {
    throw new UtaConfigError("UTA_CLIENT_ID is required");
  }

  const redirect_uri = readStr("UTA_REDIRECT_URI");
  if (!redirect_uri) {
    throw new UtaConfigError("UTA_REDIRECT_URI is required");
  }

  // Optional: omit for a public (browser/native) client using PKCE only.
  const client_secret = readSecretOrPath("UTA_CLIENT_SECRET", "UTA_CLIENT_SECRET_PATH");

  const issuer = (readStr("UTA_ISSUER") ?? DEFAULT_ISSUER).replace(/\/+$/, "");
  const api_url = (readStr("UTA_API_URL") ?? DEFAULT_API_URL).replace(/\/+$/, "");
  const scopes = readStr("UTA_SCOPES") ?? DEFAULT_SCOPES;

  _cached = {
    client_id,
    redirect_uri,
    issuer,
    api_url,
    scopes,
    client_secret,
    request_timeout_seconds: readInt("UTA_REQUEST_TIMEOUT_SECONDS", 10, 1),
    clock_skew_seconds: readInt("UTA_CLOCK_SKEW_SECONDS", 60, 0),
  };
  return _cached;
}
