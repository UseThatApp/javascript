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
 * The app's developer has not enabled the Auth & Entitlement add-on.
 * The token is fine and no retry, refresh, or re-consent will help: the
 * entitlement service is switched off for this app. Enable it on the
 * app's manage page at usethatapp.com (Integration panel → "Turn on
 * entitlement").
 */
export class UtaServiceNotEnabledError extends UtaPermissionError {}

/** A usethatapp.com endpoint returned 5xx, or the network failed. Retriable. */
export class UtaServerError extends UtaError {}
