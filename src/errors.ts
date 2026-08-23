/**
 * Error hierarchy for the UseThatApp SDK (v2, OIDC).
 *
 * Every error thrown by the public API extends {@link UtaError}.
 * Catch `UtaError` (or a specific subclass) — never a bare `Error`.
 */

export class UtaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** SDK configuration is missing or invalid. */
export class UtaConfigError extends UtaError {}

/** OIDC discovery document or JWKS could not be fetched/parsed. */
export class UtaDiscoveryError extends UtaError {}

/**
 * The authorization step failed — a `state` mismatch, a provider `error`
 * response, or a user-denied authorization. Treat as "login did not succeed".
 */
export class UtaAuthError extends UtaError {}

/**
 * A token could not be obtained or validated: token-endpoint failures
 * (code exchange / refresh), ID-token validation failures (signature,
 * issuer, audience, expiry, nonce), or a 401 from the entitlement endpoint.
 */
export class UtaTokenError extends UtaError {}

/**
 * The token is valid but the request is not permitted (403) — usually a
 * missing `entitlements` scope. When the server reports that the app's
 * developer has not enabled the entitlement service, the more specific
 * {@link UtaServiceNotEnabledError} subclass is thrown instead; existing
 * `catch` blocks testing for `UtaPermissionError` still match it.
 */
export class UtaPermissionError extends UtaError {}

/**
 * The app's developer has not enabled the Hosted sign-in add-on.
 * The token is fine and no retry, refresh, or re-consent will help:
 * Hosted sign-in is switched off for this app. The developer turns it
 * on from the app's manage hub (Integration panel → Hosted sign-in).
 */
export class UtaServiceNotEnabledError extends UtaPermissionError {}

/**
 * The License Key API could not find what you referenced. `code` says
 * what: `unknown_key` (a key we never issued — or another app's),
 * `unknown_order` (bad/expired order ref), or `unknown_license` (no such
 * license id for your app).
 */
export class UtaNotFoundError extends UtaError {
  readonly code: string;

  constructor(message: string, code = "") {
    super(message);
    this.code = code;
  }
}

/**
 * The order is genuine but its license hasn't landed yet (payment
 * webhooks run seconds behind checkout). Retry briefly.
 */
export class UtaOrderProcessingError extends UtaError {}

/** The license is terminally canceled — its key cannot be regenerated. */
export class UtaLicenseCanceledError extends UtaError {}

/**
 * A usethatapp.com endpoint returned 5xx or 429, or the network failed.
 * Retriable. On a rate limit (429), `retryAfter` carries the server's
 * `Retry-After` header in seconds — use it as the backoff interval instead
 * of guessing. `null` when the server sent none (5xx, network errors).
 */
export class UtaServerError extends UtaError {
  readonly retryAfter: number | null;

  constructor(message: string, retryAfter: number | null = null) {
    super(message);
    this.retryAfter = retryAfter;
  }
}
