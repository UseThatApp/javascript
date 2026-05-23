import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";

import { UtaConfigError } from "./errors.js";

/**
 * Default (production) marketplace public key.
 *
 * Maintainers: paste the marketplace's production RSA public key (PEM) here
 * so end developers don't have to configure `UTA_MARKET_PUBLIC_KEY`
 * themselves. Leave as `null` to require explicit configuration.
 */
export const DEFAULT_MARKET_PUBLIC_KEY_PEM: string | null = `\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4geFPJUHrBAsG+v9IO+V
nIAK8ZNrHcoLVYPdLE58AyTGtZsg3WkbuJBYtu4dewjPvyFzX5amw7jAf3xNYQb5
DWBSEBDKuGAAyhUFT2/bV7hK+iHchWh/kozR6tyIM5LruL97F+YUDo3EsZF83+19
4tATb75EZdtFz3W2IbuOFId4kYlKnI8yGf2b0wNK37X+v12D0D8gfwPq6v2LnPQ0
YnE9nGtWopMfVVBN+61BdFq+/qeFPBNVuN2VI+Zc32pE0/MyutcoewaG0ZMGCyZC
AejI47yWCnEUGLtto1G5TIkXqII9wExS5qhyAFjn2RR053qw5HD+CuCQ1GTZWt7l
VQIDAQAB
-----END PUBLIC KEY-----
`;

export interface UtaConfig {
  readonly app_id: string;
  readonly private_key: KeyObject;
  readonly market_public_key: KeyObject;
  readonly api_url: string;
  readonly clock_skew_seconds: number;
  readonly request_timeout_seconds: number;
}

export interface UtaConfigOverrides {
  app_id?: string;
  private_key?: string | KeyObject;
  private_key_path?: string;
  market_public_key?: string | KeyObject;
  market_public_key_path?: string;
  api_url?: string;
  clock_skew_seconds?: number;
  request_timeout_seconds?: number;
}

let _cached: UtaConfig | null = null;
let _overrides: UtaConfigOverrides = {};

/**
 * Decode a PEM string that uses C-style escapes (e.g. literal `\n` for
 * newline). Common when a multi-line PEM is shoved into a single env var.
 */
function pemFromUnicodeEscaped(pemStr: string): string {
  if (!pemStr.includes("\\n") && !pemStr.includes("\\r")) {
    return pemStr;
  }
  return pemStr
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\\\/g, "\\");
}

function coercePrivateKey(value: string | KeyObject): KeyObject {
  if (typeof value !== "string") {
    return value;
  }
  try {
    return createPrivateKey(pemFromUnicodeEscaped(value));
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaConfigError(`UTA_PRIVATE_KEY is not a valid PEM RSA key: ${err}`);
  }
}

function coercePublicKey(value: string | KeyObject): KeyObject {
  if (typeof value !== "string") {
    return value;
  }
  try {
    return createPublicKey(pemFromUnicodeEscaped(value));
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaConfigError(
      `UTA_MARKET_PUBLIC_KEY is not a valid PEM RSA public key: ${err}`,
    );
  }
}

function readRaw(name: string): unknown {
  const overrideKey = name.toLowerCase().replace(/^uta_/, "") as keyof UtaConfigOverrides;
  const override = _overrides[overrideKey];
  if (override !== undefined) {
    return override;
  }
  const env = process.env[name];
  return env === undefined ? undefined : env;
}

/**
 * Resolve a (direct, path) settings pair. Returns the direct value if
 * set; otherwise reads the file at the path and returns its contents
 * as a UTF-8 string. Returns `undefined` if neither is set.
 */
function resolveKeyMaterial(
  directName: string,
  pathName: string,
): string | KeyObject | undefined {
  const direct = readRaw(directName);
  if (direct !== undefined) {
    return direct as string | KeyObject;
  }
  const path = readRaw(pathName);
  if (path === undefined) {
    return undefined;
  }
  if (typeof path !== "string") {
    throw new UtaConfigError(`${pathName} must be a filesystem path string`);
  }
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaConfigError(`${pathName}=${path}: could not read file: ${err}`);
  }
}

function readInt(name: string, fallback: number): number {
  const raw = readRaw(name);
  if (raw === undefined) return fallback;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return Math.trunc(raw);
  }
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
 * Override one or more settings at runtime (useful for tests or apps
 * that prefer programmatic configuration over env vars). Calling this
 * clears the cached config.
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

  const appIdRaw = readRaw("UTA_APP_ID");
  if (typeof appIdRaw !== "string" || appIdRaw === "") {
    throw new UtaConfigError("UTA_APP_ID is required");
  }
  const app_id = appIdRaw;

  const privRaw = resolveKeyMaterial("UTA_PRIVATE_KEY", "UTA_PRIVATE_KEY_PATH");
  if (privRaw === undefined) {
    throw new UtaConfigError(
      "UTA_PRIVATE_KEY or UTA_PRIVATE_KEY_PATH is required",
    );
  }
  if (typeof privRaw !== "string" && typeof privRaw !== "object") {
    throw new UtaConfigError("UTA_PRIVATE_KEY must be a PEM string or KeyObject");
  }
  const private_key = coercePrivateKey(privRaw as string | KeyObject);

  let marketRaw: string | KeyObject | undefined = resolveKeyMaterial(
    "UTA_MARKET_PUBLIC_KEY",
    "UTA_MARKET_PUBLIC_KEY_PATH",
  );
  if (marketRaw === undefined) {
    if (DEFAULT_MARKET_PUBLIC_KEY_PEM === null) {
      throw new UtaConfigError(
        "UTA_MARKET_PUBLIC_KEY or UTA_MARKET_PUBLIC_KEY_PATH is required "
        + "(no bundled default available)",
      );
    }
    marketRaw = DEFAULT_MARKET_PUBLIC_KEY_PEM;
  }
  if (typeof marketRaw !== "string" && typeof marketRaw !== "object") {
    throw new UtaConfigError(
      "UTA_MARKET_PUBLIC_KEY must be a PEM string or KeyObject",
    );
  }
  const market_public_key = coercePublicKey(marketRaw as string | KeyObject);

  const apiUrlRaw = readRaw("UTA_API_URL");
  let api_url = "https://usethatapp.com";
  if (apiUrlRaw !== undefined) {
    if (typeof apiUrlRaw !== "string") {
      throw new UtaConfigError("UTA_API_URL must be a string");
    }
    api_url = apiUrlRaw;
  }
  api_url = api_url.replace(/\/+$/, "");

  const clock_skew_seconds = readInt("UTA_CLOCK_SKEW_SECONDS", 60);
  const request_timeout_seconds = readInt("UTA_REQUEST_TIMEOUT_SECONDS", 10);

  _cached = {
    app_id,
    private_key,
    market_public_key,
    api_url,
    clock_skew_seconds,
    request_timeout_seconds,
  };
  return _cached;
}
