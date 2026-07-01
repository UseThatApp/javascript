/**
 * OIDC discovery + JWKS, cached per issuer.
 *
 * The discovery document is fetched once and cached. JWKS is handled by
 * jose's `createRemoteJWKSet`, which fetches lazily, caches, and refetches
 * on an unknown `kid` (key rotation) with a built-in cooldown.
 */

import { createRemoteJWKSet } from "jose";

import type { UtaConfig } from "./config.js";
import { UtaDiscoveryError } from "./errors.js";
import { errMessage, fetchWithTimeout } from "./http.js";

export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  [key: string]: unknown;
}

type JwkSet = ReturnType<typeof createRemoteJWKSet>;

const metadataCache = new Map<string, OidcMetadata>();
const jwksCache = new Map<string, JwkSet>();

export async function getMetadata(cfg: UtaConfig): Promise<OidcMetadata> {
  const cached = metadataCache.get(cfg.issuer);
  if (cached) return cached;

  const url = cfg.issuer + "/.well-known/openid-configuration";
  let data: unknown;
  try {
    const resp = await fetchWithTimeout(url, {}, cfg.request_timeout_seconds);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
  } catch (e) {
    throw new UtaDiscoveryError(`failed to fetch OIDC discovery from ${url}: ${errMessage(e)}`);
  }

  if (data === null || typeof data !== "object") {
    throw new UtaDiscoveryError("discovery document is not a JSON object");
  }
  const meta = data as OidcMetadata;
  for (const key of ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    if (typeof meta[key] !== "string") {
      throw new UtaDiscoveryError(`discovery document missing '${key}'`);
    }
  }

  metadataCache.set(cfg.issuer, meta);
  return meta;
}

/** Return a jose JWKS resolver for the discovered `jwks_uri` (cached). */
export function getJwks(meta: OidcMetadata): JwkSet {
  let jwks = jwksCache.get(meta.jwks_uri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(meta.jwks_uri));
    jwksCache.set(meta.jwks_uri, jwks);
  }
  return jwks;
}

/** Clear cached discovery + JWKS. Mostly useful in tests. */
export function resetDiscoveryCache(): void {
  metadataCache.clear();
  jwksCache.clear();
}
