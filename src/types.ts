/**
 * Public types for the UseThatApp SDK (v2, OIDC).
 *
 * The v2 flow shares **only** a pairwise pseudonymous `sub` — no email,
 * username, or other PII. `sub` is stable for a user *within your app* but
 * differs across apps, so it is safe as your local user key yet cannot be
 * correlated against other apps.
 */

/** Opaque, JSON-serializable login state. Stash in the session between
 * {@link beginLogin} and {@link completeLogin}; treat its fields as opaque. */
export interface UtaFlowState {
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly redirectUri: string;
}

/** The result of a completed OIDC login. */
export interface UtaSession {
  /** Pairwise pseudonymous user id. Stable per-app; use as your user key. */
  readonly sub: string;
  /** Bearer token for {@link getEntitlement}. */
  readonly access_token: string;
  /** Unix seconds at which `access_token` expires. */
  readonly expires_at: number;
  /** Use with {@link refresh} to obtain a fresh session, if present. */
  readonly refresh_token: string | null;
  /** Raw OIDC ID token (JWT). Pass to {@link logoutUrl}. */
  readonly id_token: string | null;
  /** Space-separated granted scopes. */
  readonly scope: string;
  readonly token_type: string;
  /** Validated ID-token claims (`sub` plus standard OIDC claims). */
  readonly claims: Record<string, unknown>;
}

/**
 * A user's live license state for your app. Always reflects the current
 * license on usethatapp.com — re-query whenever you need an authoritative
 * answer (cheap, and cacheable on your side if you wish).
 */
export interface Entitlement {
  /** True if the user may use the app (an active license or a free tier). */
  readonly entitled: boolean;
  /** Product/plan display name, or `null` when not entitled. */
  readonly version: string | null;
  /** Stable product UUID — prefer this over `version` for gating logic. */
  readonly product_id: string | null;
  /** `active`/`trialing`/`one_time_active`/`free`/`none`/… */
  readonly status: string;
  /** True when the entitlement comes from the app's free tier. */
  readonly is_free: boolean;
  /** ISO date the current license period ends, or `null`. */
  readonly period_end: string | null;
  /** The full decoded response, for forward-compatibility. */
  readonly raw: Record<string, unknown>;
}
