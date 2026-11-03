# Changelog

All notable changes to this project are documented in this file. This
project adheres to [Semantic Versioning](https://semver.org/).

## [2.3.1] - 2026-11-02

### Documentation

- README rewritten around the default integration: license keys first,
  then prices and buy links, with Hosted sign-in as the optional add-on.
  Corrected stale claims (purchases are open to international buyers;
  external sales is on by default; `Entitlement.product_id` already
  carries the `prod_…` id; a cancellation keeps access until
  `period_end`; seller apps always use a confidential client, so the
  secret is never optional). The changelog that was duplicated in the
  README, and the v1 migration table, now live only here.
- New `examples/license-keys-express` app for the license-key flow.

## [2.3.0] - 2026-10-29

### Added

- `Entitlement.is_trial` and `LicenseState.is_trial`: true while the user
  is in a free trial of a paid plan (entitled, nothing charged yet;
  `period_end` is the conversion date). Explicit so integrations never
  string-match `status === "trialing"`. Servers that predate the field
  decode as `false`.

## [2.2.0] - 2026-08-25

### Fixed (pre-release code review)

- `Entitlement.product_id` now carries the same
  fall-back-to-`product_public_id` parsing as `LicenseState.product_id`,
  so the alias contract ("either works") holds in both verification
  modes — previously only the License Key API parser had the fallback.
- `userinfo()` and the token endpoint now speak the same 429/5xx
  contract as every other endpoint: 429 throws retriable
  `UtaServerError` with `retryAfter` (a throttled token refresh is no
  longer a `UtaTokenError`, which read as "log the user out"), and
  their error messages cap quoted bodies like everywhere else.
- The ~200-character error-body cap now applies to JSON bodies too — a
  multi-kilobyte JSON error (gateway error with an embedded traceback
  field) was previously quoted whole — and the truncation suffix
  reports the amount actually cut.
- The License Key API decode path shares `apiGetJson`'s object
  validation: a JSON array response now throws instead of silently
  decoding into an all-defaults (entitled: false) `LicenseState`.
- `configure({client_secret_path})` now outranks an environment
  `UTA_CLIENT_SECRET`: secret-pair precedence is decided per layer
  (overrides → environment), not per key.
- `ALLOWED_OVERRIDES` is derived from `UtaConfigOverrides` via
  `satisfies`, so the typo guard can never drift into rejecting a
  TypeScript-valid option.
- `src/version.ts` is generated from `package.json` at build time (and
  `prepublishOnly` runs the build), so `SDK_VERSION` can no longer ship
  one release behind.
- A 202 from `validateLicenseKey`/`regenerateLicenseKey` (off-contract
  there) no longer throws the order-specific "retry in a few seconds"
  `UtaOrderProcessingError`; only `getOrder` opts into 202 semantics.
- The `UtaServiceNotEnabledError` message points at the manage page on
  `https://www.usethatapp.com` — not the resolved `api_url`, which a
  `configure({api_url})` override can aim at a host with no manage UI.
- README: the 403 row and changelog name the add-on by its current
  public name (Hosted sign-in), the 429/5xx rows document `retryAfter`,
  the License Key API description no longer references the unexported
  `resolveClientSecret()`, and the changelog section is dated 2.2.0 to
  match CHANGELOG.md and package.json.

### Added

- **License Key API** (server-side, bring-your-own-auth MoR
  verification): `validateLicenseKey(key)`, `getOrder(ref)` for the
  `uta_order` checkout handback, and `regenerateLicenseKey(licenseId)`
  as the compromise kill switch — all authenticated with your app's
  client credentials (`UTA_CLIENT_SECRET` required; no redirect URI
  needed in keys mode). New `LicenseState` type and typed errors:
  `UtaNotFoundError` (with `.code`), `UtaOrderProcessingError`,
  `UtaLicenseCanceledError`.
- `UtaServiceNotEnabledError` (subclass of `UtaPermissionError`), raised
  when the entitlement endpoint returns `403 service_not_enabled`: the
  app's developer has not enabled the Hosted sign-in add-on. Existing
  `UtaPermissionError` handling catches it unchanged.
- `LicenseState.product_id` — an equal-valued alias of
  `product_public_id` (the platform's post-cutover `prod_…` pair, the
  same contract as the entitlement endpoint), with a parser fallback
  against servers that predate the cutover.

- `UtaServerError.retryAfter` — the server's `Retry-After` header in
  seconds on a 429 (`null` otherwise), so backoff loops can use the
  interval the platform actually sent instead of guessing.
- `SDK_VERSION` — the installed version as a string, for build checks,
  log lines, and bug reports; the `exports` map also now exposes
  `./package.json` for tooling.

### Fixed

- `configure()` now throws `UtaConfigError` on an unknown option name,
  matching the Python SDK. TypeScript's excess-property check only
  guards object literals, so a typo from plain JavaScript (every
  framework sample on the docs site) was silently ignored — and the
  setting it was meant to change kept its default, e.g. `api_url`
  still pointing at production.
- `LicenseState` fields are `readonly`, matching every other public
  interface.
- The `getPrices` JSDoc claimed `Entitlement.product_id` still carried
  a legacy UUID "until the platform's identifier cutover"; the cutover
  shipped, and the type's own doc said so — the two tooltips now agree.
- The `UtaServiceNotEnabledError` message named the add-on by its
  retired public name ("Auth & Entitlement") and hardcoded
  `usethatapp.com`; it now says "Hosted sign-in" and points at the
  configured `UTA_API_URL` host.
- Non-JSON error bodies (HTML error pages) are collapsed and capped at
  ~200 characters when quoted into error messages, instead of inlining
  the entire page.

## [2.1.0] - 2026-08-11

Thin support for selling your app from your own website (hosted purchase
links, buyer management page, public pricing API), plus OIDC hardening.
The new surface is additive, but the hardening tightens some previously
lax behavior — see *Security* and *Changed* below before upgrading.

### Added

- `purchaseUrl(priceId, { next, ref, email })` — pure builder for the hosted
  checkout URL of a price.
- `manageUrl({ next })` — pure builder for the buyer's subscription-management
  page URL for your app.
- `getAppInfo()` → `AppInfo` — the app's public listing info (anonymous, no
  auth).
- `getPrices()` → `AppPrices` — the app's public price list (anonymous, no
  auth); each `UtaPrice` carries a ready-made `buy_url` and a `product_id`
  matching `Entitlement.product_public_id` (not the legacy
  `Entitlement.product_id` UUID).
- New types: `AppInfo`, `AppPrices`, `UtaPrice`.
- `Entitlement.product_public_id` — the opaque public product identifier
  (`prod_…`) matching `UtaPrice.product_id` from the pricing API. New
  integrations should gate on it; `Entitlement.product_id` currently
  carries a legacy UUID and will converge on the same `prod_…` value.

### Security

These close real gaps in 2.0.0's OIDC flow. Each one turns a case that
used to pass silently into a thrown error, so an integration relying on
the old leniency will now see an exception instead.

- **Discovery issuer is verified.** A discovery document whose `issuer`
  does not match the configured `UTA_ISSUER` is rejected with
  `UtaDiscoveryError` (and never cached). Previously ID tokens were
  validated against whatever `issuer`/`jwks_uri` the document declared,
  so a misconfigured or hostile discovery endpoint could get tokens from
  a different issuer accepted.
- **A missing nonce no longer skips replay protection.** `completeLogin`
  throws `UtaAuthError` when `flowState` lacks `nonce`/`codeVerifier` —
  e.g. when a session layer drops fields — instead of silently omitting
  the nonce check.
- **`userinfo()` rejects every non-2xx response** (403 →
  `UtaPermissionError`), and `refresh()` throws `UtaTokenError` on a
  missing/empty `sub`. Previously a 403/404/400 error body was returned
  as claims, producing a session with `sub === ""` that collided every
  affected user onto one identity.
- **`beginLogin` rejects reserved `extraParams`.** Passing a key that
  collides with `state`, `nonce`, `code_challenge`, `redirect_uri`,
  `client_id`, … now throws `UtaError` rather than overwriting the value
  recorded in `flowState` and breaking CSRF/PKCE protection.
- **An empty `UTA_CLIENT_SECRET` no longer shadows
  `UTA_CLIENT_SECRET_PATH`.** A blank env var now falls through to the
  mounted secret file instead of demoting the app to a public client.

### Changed

- Request timeouts now cover the response body, not just the headers. A
  server that sends headers and then stalls fails after
  `UTA_REQUEST_TIMEOUT_SECONDS` instead of hanging indefinitely.
- `UTA_REQUEST_TIMEOUT_SECONDS` must be ≥ 1 and `UTA_CLOCK_SKEW_SECONDS`
  ≥ 0; out-of-range values raise `UtaConfigError` at config load.
  Previously `0` was accepted and aborted every request immediately.
- `getEntitlement` maps 429 to `UtaServerError` (retriable with backoff)
  instead of a generic non-retriable `UtaError`, matching the public
  pricing endpoints.

### Fixed

- Gating guidance: the quickstart and `getPrices` docs now compare a
  price's `product_id` against `Entitlement.product_public_id`. The old
  wording pointed at `Entitlement.product_id`, whose legacy UUID makes
  the comparison false for every buyer.
- The example apps map `UtaServerError` to HTTP 502 rather than 400, so
  a provider outage is not reported as a client error.

## [2.0.0]

Breaking rewrite onto standard OAuth2 / OpenID Connect. usethatapp.com is now
an OpenID Provider; the SDK is a framework-agnostic OIDC client.

### Migrating from 1.x

| 1.x | 2.x |
|---|---|
| `getUser(payload)` (decrypt envelope) | `beginLogin()` + `completeLogin()` (OIDC) |
| `UtaUser.user_key` | `UtaSession.sub` (pairwise, stable per app) |
| `getVersion(userKey) => string | null` | `getEntitlement(accessToken) => Entitlement` |
| RSA keys (`UTA_PRIVATE_KEY`, market key) | OAuth client (`UTA_CLIENT_ID` / `UTA_CLIENT_SECRET`) |
| `UTA_APP_ID` | Gone: the client id identifies your app |
| `utaLaunchView` Express helper | Gone: wire your own callback route |

### Removed

- `getUser` / `getUserFromRequest` and the encrypted launch-envelope handling.
- `getVersion` / `clearVersionCache` and the process-local version cache.
- `utaLaunchView` Express helper — the SDK ships no framework-specific code.
- `UtaUser` (and its `user_key` / `version_hint`).
- RSA-key config (`UTA_PRIVATE_KEY[_PATH]`, `UTA_MARKET_PUBLIC_KEY[_PATH]`)
  and `UTA_APP_ID`.

### Added

- OIDC login: `beginLogin()` → `{ authorizationUrl, flowState }` (auth code +
  PKCE); `completeLogin({ code, state, flowState })` → `UtaSession`, validating
  `state`, exchanging the code, and verifying the ID token (signature via JWKS,
  `iss`/`aud`/`exp`/`nonce`) with `jose`.
- `refresh(refreshToken)`, `userinfo(accessToken)`, `logoutUrl({...})`.
- `getEntitlement(accessToken)` → `Entitlement(entitled, version, product_id,
  status, is_free, period_end)`, the Bearer replacement for `getVersion`.
- `UtaSession` (pairwise pseudonymous `sub` + tokens), `Entitlement`,
  `UtaFlowState`.
- New config: `UTA_CLIENT_ID`, `UTA_CLIENT_SECRET[_PATH]`, `UTA_REDIRECT_URI`,
  `UTA_ISSUER`, `UTA_SCOPES`.
- New typed errors: `UtaDiscoveryError`, `UtaAuthError`, `UtaTokenError`,
  `UtaPermissionError`.

### Changed

- One runtime dependency: `jose`. Identity is a pairwise, per-app pseudonymous
  `sub` — stable within your app, uncorrelatable across apps.

## [1.0.0]

Breaking rewrite for the (now superseded) webhook-based launch-envelope handoff.
