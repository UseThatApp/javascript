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
 * (Render Secret Files, Fly volumes, k8s secret volumes, …). The direct
 * value wins if both are set.
 */
function readSecretOrPath(directName: string, pathName: string): string | undefined {
  const direct = readStr(directName);
  if (direct !== undefined) return direct;
  const path = readStr(pathName);
  if (path === undefined) return undefined;
  try {
    return readFileSync(path, "utf8").trim();
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaConfigError(`${pathName}=${path}: could not read file: ${err}`);
  }
}

function readInt(name: string, fallback: number): number {
  const raw = readRaw(name);
  if (raw === undefined) return fallback;
  if (typeof raw === "number" && Number.isFinite(raw)) return Math.trunc(raw);
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    const n = parseInt(trimmed, 10);
    if (Number.isNaN(n) || String(n) !== trimmed) {
      throw new UtaConfigError(`${name} must be an integer`);
    }
    return n;
  }
  throw new UtaConfigError(`${name} must be an integer`);
}

/**
 * Override one or more settings at runtime (useful for tests or apps that
 * prefer programmatic configuration over env vars). Clears the cached config.
 */
export function configure(overrides: UtaConfigOverrides): void {
  _overrides = { ..._overrides, ...overrides };
  _cached = null;
}

/** Drop the cached config and all programmatic overrides. */
export function resetConfig(): void {
  _cached = null;
  _overrides = {};
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
    request_timeout_seconds: readInt("UTA_REQUEST_TIMEOUT_SECONDS", 10),
    clock_skew_seconds: readInt("UTA_CLOCK_SKEW_SECONDS", 60),
  };
  return _cached;
}
