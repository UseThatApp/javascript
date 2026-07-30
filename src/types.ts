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
 * Your app's public listing info, from the anonymous public API
 * ({@link getAppInfo}). No auth needed — safe to serve straight into a
 * marketing or pricing page.
 */
export interface AppInfo {
  /** Your app's OAuth client id (echoes the one you queried with). */
  readonly client_id: string;
  /** The app's display name. */
  readonly name: string;
  /** The app's short tagline. */
  readonly tagline: string;
  /** `"marketplace"` or `"external"` — where the app is sold. */
  readonly listing_mode: string;
  /** The app's own website URL. */
  readonly url: string;
  /** The app's page on the usethatapp.com marketplace. */
  readonly marketplace_url: string;
  /** The full decoded response, for forward-compatibility. */
  readonly raw: Record<string, unknown>;
}

/** One purchasable price for your app, from {@link getPrices}. */
export interface UtaPrice {
  /** Opaque public price id (`prc_…`). Pass to {@link purchaseUrl}. */
  readonly public_id: string;
  /** Opaque product identifier (`prod_…`) — matches
   * {@link Entitlement.product_public_id}, so you can map a purchase
   * option to your gating logic (and `Entitlement.product_id` after the
   * platform's identifier cutover). */
  readonly product_id: string;
  /** Product/plan display name. */
  readonly product_name: string;
  /** Decimal string, e.g. `"10.00"`. Kept as a string so the SDK imposes
   * no float precision on money. */
  readonly amount: string;
  /** Lowercase ISO currency code, e.g. `"usd"`. */
  readonly currency: string;
  /** True for subscriptions, false for one-time purchases. */
  readonly is_recurring: boolean;
  /** `"day"`/`"week"`/`"month"`/`"year"`, or `null` for one-time prices. */
  readonly frequency: string | null;
  /** Ready-made hosted checkout link for this price. */
  readonly buy_url: string;
}

/** Your app's public price list, from {@link getPrices}. */
export interface AppPrices {
  /** Your app's OAuth client id (echoes the one you queried with). */
  readonly client_id: string;
  /** The app's display name. */
  readonly app_name: string;
  /** True if the app offers a free tier alongside the paid prices. */
  readonly has_free_tier: boolean;
  /** The purchasable prices, ready to render as a pricing table. */
  readonly prices: readonly UtaPrice[];
  /** The full decoded response, for forward-compatibility. */
  readonly raw: Record<string, unknown>;
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
  /** Stable product identifier — prefer this over `version` for gating
   * logic. Currently a legacy UUID; after the platform's identifier
   * cutover it carries the same opaque `prod_…` value as
   * `product_public_id`. */
  readonly product_id: string | null;
  /** Opaque public product identifier (`prod_…`) — matches
   * {@link UtaPrice.product_id} from the pricing API. New integrations
   * should gate on this field. */
  readonly product_public_id: string | null;
  /** `active`/`trialing`/`one_time_active`/`free`/`none`/… */
  readonly status: string;
  /** True when the entitlement comes from the app's free tier. */
  readonly is_free: boolean;
  /** ISO date the current license period ends, or `null`. */
  readonly period_end: string | null;
  /** The full decoded response, for forward-compatibility. */
  readonly raw: Record<string, unknown>;
}
