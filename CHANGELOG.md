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

## [2.1.0] - 2026-08-11

The purchase surface: `purchaseUrl`, `manageUrl`, `getPrices`,
`getAppInfo`, and `Entitlement.product_public_id`. Published to npm.

## [2.0.0] - 2026-06-21

OpenID Connect rewrite: `beginLogin`/`completeLogin`, `getEntitlement`,
RP-initiated logout. Replaces the 1.x launch-envelope interface.

## [1.0.0] - 2026-05-21

Initial release: encrypted launch-envelope verification.
