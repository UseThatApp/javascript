# Changelog

All notable changes to this project are documented in this file. This
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.2.0] - 2026-08-22

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

### Fixed

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
