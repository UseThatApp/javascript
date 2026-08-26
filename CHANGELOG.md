# Changelog

All notable changes to this project are documented in this file. This
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

## [2.1.0] and earlier

Releases before 2.2.0 predate this changelog. 2.1.0 (on npm) added the
purchase surface (`purchaseUrl`, `manageUrl`, `getPrices`,
`getAppInfo`) and `Entitlement.product_public_id`; 2.0.0 was the
OpenID Connect rewrite.
