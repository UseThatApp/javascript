# usethatapp

JavaScript/TypeScript SDK for [usethatapp.com](https://usethatapp.com).
usethatapp.com is an **OpenID Connect provider**: this SDK logs a user in
through the marketplace, identifies them by a privacy-preserving `sub`, and
tells you their **live license entitlement** for your app.

**Framework-agnostic.** The SDK never touches your web framework — it takes
and returns plain strings and one JSON-serializable `flowState` object. You
wire the three framework-specific bits yourself (read the callback query
params, store `flowState` in your session, issue the redirect). One runtime
dependency: [`jose`](https://github.com/panva/jose) for ID-token validation.

> **v2.0 is a breaking rewrite.** The v1 launch-envelope / `user_key` /
> `getVersion` handoff is replaced by standard OAuth2/OIDC. See the
> *Migrating from v1* section and the changelog below.

**Requires:** Node.js 18+ (uses global `fetch` and WebCrypto).

## How it works

1. **Login (redirect).** Start a login with `beginLogin()`, send the user to
   usethatapp.com to authenticate, and finish in your callback with
   `completeLogin()`. You get a session carrying the user's `sub` (a stable,
   **per-app**, pseudonymous id — no PII) and OAuth tokens.
2. **Entitlement (Bearer query).** Call `getEntitlement(accessToken)`
   whenever you need the user's current license. Always authoritative — a
   canceled license stops being entitled immediately.

`sub` is **pairwise**: stable for a user within *your* app, different in
every other app, so it can't be correlated across apps. Use it as your local
user key — and key off `sub`, never an email (we never share one).

## Install

```bash
npm install usethatapp
```

## Settings

Read from `process.env` by default; override any setting with `configure({...})`.

| Name                          | Required | Purpose                                                       |
|-------------------------------|----------|---------------------------------------------------------------|
| `UTA_CLIENT_ID`               | yes      | Your app's OAuth client id (from the dashboard).             |
| `UTA_REDIRECT_URI`            | yes      | Your registered callback URL.                                |
| `UTA_CLIENT_SECRET`           | yes*     | Client secret. *Omit for a public (browser/native) PKCE client.|
| `UTA_CLIENT_SECRET_PATH`      | no       | Read the secret from a mounted file instead (Render/k8s/Fly).|
| `UTA_ISSUER`                  | no       | Defaults to `https://www.usethatapp.com/o`.                  |
| `UTA_API_URL`                 | no       | Defaults to `https://www.usethatapp.com`.                    |
| `UTA_SCOPES`                  | no       | Defaults to `openid entitlements`.                           |
| `UTA_CLOCK_SKEW_SECONDS`      | no       | ID-token validation leeway. Defaults to `60`.                |
| `UTA_REQUEST_TIMEOUT_SECONDS` | no       | Defaults to `10`.                                            |

## Public API

```ts
import {
  beginLogin,      // () => { authorizationUrl, flowState }
  completeLogin,   // ({ code, state, flowState }) => UtaSession
  getEntitlement,  // (accessToken) => Entitlement
  refresh,         // (refreshToken) => UtaSession
  userinfo,        // (accessToken) => { sub }
  logoutUrl,       // ({ idToken, postLogoutRedirectUri }) => string
  purchaseUrl,     // (priceId, { next, ref, email }) => string
  manageUrl,       // ({ next }) => string
  getAppInfo,      // () => AppInfo
  getPrices,       // () => AppPrices
  configure, resetConfig,
  type UtaSession, type Entitlement, type UtaFlowState,
  type AppInfo, type AppPrices, type UtaPrice,
  // errors:
  UtaError, UtaConfigError, UtaDiscoveryError, UtaAuthError,
  UtaTokenError, UtaPermissionError, UtaServiceNotEnabledError,
  UtaNotFoundError, UtaOrderProcessingError, UtaLicenseCanceledError,
  UtaServerError,
} from "usethatapp";
```

## Quickstart — any framework

```js
import { beginLogin, completeLogin, getEntitlement } from "usethatapp";

// 1) Start login — however your framework spells "redirect":
const { authorizationUrl, flowState } = await beginLogin();
saveToSession("utaFlow", flowState);        // JSON-serializable
res.redirect(authorizationUrl);

// 2) In your callback (reads ?code=...&state=... off the request).
//    On cancel/deny the provider sends ?error=... and no code — handle it first:
if (req.query.error) return res.redirect("/");   // login was canceled
const session = await completeLogin({
  code: req.query.code,
  state: req.query.state,
  flowState: loadFromSession("utaFlow"),
});
saveToSession("utaSub", session.sub);
saveToSession("utaAccessToken", session.access_token);

// 3) Anywhere you gate features:
const ent = await getEntitlement(loadFromSession("utaAccessToken"));
if (ent.entitled && ent.product_public_id === "prod_...") { /* ... */ }
```

Runnable demos live under [`examples/`](./examples/) — documentation only;
nothing framework-specific ships in the package.

## Error mapping

`getEntitlement` maps status codes to typed errors:

| Status | Error                | Meaning                                        |
|--------|----------------------|------------------------------------------------|
| 401    | `UtaTokenError`      | Access token invalid/expired — re-auth/refresh.|
| 403 (`insufficient_scope`)  | `UtaPermissionError`        | Token lacks the `entitlements` scope. |
| 403 (`service_not_enabled`) | `UtaServiceNotEnabledError` | The Hosted sign-in add-on is switched off for this app. No retry, refresh, or re-consent will help — enable it on the app's manage page at www.usethatapp.com (Integration panel). |
| 400    | `UtaError`           | Client not linked to an app (misconfig).       |
| 429    | `UtaServerError`     | Rate limited — back off; `e.retryAfter` carries the server's `Retry-After` seconds (or `null`). |
| 5xx    | `UtaServerError`     | Retriable with backoff; `e.retryAfter` when the server sent one. |

All inherit from `UtaError` — catch that for a single `catch` clause.
`UtaServiceNotEnabledError` extends `UtaPermissionError`, so existing
`catch` blocks that test for `UtaPermissionError` keep working unchanged.

## License Key API — bring your own auth

If you keep your own auth (Auth0, Clerk, homegrown) and use UseThatApp
purely as merchant of record, skip the OIDC flow entirely and verify
purchases with license keys. Server-side only; set `UTA_CLIENT_SECRET`
(`UTA_REDIRECT_URI` is not needed for this mode).

```js
import { getOrder, regenerateLicenseKey, validateLicenseKey } from "usethatapp";

// 1) The buyer returns from checkout with ?uta_order=... — exchange it
//    for their key and link it to YOUR signed-in user. No email matching.
const order = await getOrder(req.query.uta_order); // UtaOrderProcessingError → retry briefly
await db.save({ user: currentUser, licenseKey: order.license_key, licenseId: order.license_id });

// 2) Any time you need the truth (app start, feature gate, cron):
const state = await validateLicenseKey(storedKey); // LicenseState
if (state.entitled) { /* cache against state.period_end */ }
// canceled purchases return entitled=false, status="canceled" — an
// answer, not an exception. UtaNotFoundError means a key that was
// never issued for your app.

// 3) Compromised key? Rotate it — the old key dies instantly:
const rotated = await regenerateLicenseKey(licenseId); // rotated.license_key is the new key
```

Buyers can always re-view their key on their UseThatApp management
page, so "I lost my key" needs no support ticket and no rotation.

## Purchase links & pricing

usethatapp.com can sell your app directly from your own website: hosted
checkout links, a buyer management page, and a public pricing API. The SDK
wraps these thinly — `purchaseUrl`/`manageUrl` are pure URL builders (no
network), and the pricing API needs **no auth** at all.

The natural upgrade CTA: when an entitlement comes back not entitled, send
the user to a purchase link.

```js
import { getEntitlement, purchaseUrl, manageUrl } from "usethatapp";

const ent = await getEntitlement(accessToken);
if (!ent.entitled) {
  // Hosted checkout for a specific price (id from getPrices()):
  return res.redirect(purchaseUrl("prc_...", { next: "https://yourapp.example/welcome" }));
}
// Existing buyers manage/cancel their subscription here:
const billingLink = manageUrl({ next: "https://yourapp.example/settings" });
```

`purchaseUrl` options: `next` must be an HTTPS URL on your app's registered
domain (validated server-side — invalid values show the buyer a
"misconfigured link" page; omit it to land on your registered Login URL),
`ref` credits an affiliate code, and `email` prefills the buyer's email.

Render pricing from `getPrices()` instead of hardcoding amounts — server-side,
for example:

```js
import { getPrices } from "usethatapp";

const { app_name, has_free_tier, prices } = await getPrices();
const rows = prices.map((p) => {
  const cadence = p.is_recurring ? `/${p.frequency}` : " one-time";
  // p.amount is a decimal string like "10.00" — format, don't parseFloat.
  return `<tr><td>${p.product_name}</td>` +
    `<td>${p.amount} ${p.currency.toUpperCase()}${cadence}</td>` +
    `<td><a href="${p.buy_url}">Buy</a></td></tr>`;
});
```

Each price's `product_id` is the opaque `prod_…` identifier to gate on —
compare it against **`Entitlement.product_public_id`** (`Entitlement.product_id`
still carries the legacy UUID until the platform's identifier cutover, after
which both fields carry the same `prod_…` value). Each `buy_url` is the
ready-made hosted checkout link (equivalent to `purchaseUrl(p.public_id)`).

Notes: the pricing API is anonymous and CORS-enabled; UseThatApp is the
merchant of record; purchases are currently **US-only**; and buy links 404
until external sales is enabled for your app (currently in beta). Details at
[docs.usethatapp.com](https://docs.usethatapp.com).

## Signing out

Sign-out is RP-initiated: redirect the user to `logoutUrl({ idToken })`. Both
outcomes — they confirm, or they choose "Stay signed in" — return to your
`postLogoutRedirectUri`, so you **can't** tell which happened from the redirect
alone.

So **don't clear your session when you start logout.** Reconcile on return
using the token instead: a confirmed logout revokes it, so your next
`getEntitlement()` throws `UtaTokenError` (401) — drop the token then. If they
stayed signed in, the token is still valid and they keep their session.
Clearing eagerly logs the user out of your app even when they chose to stay.

## Migrating from v1

| v1                                       | v2                                              |
|------------------------------------------|-------------------------------------------------|
| `getUser(payload)` (decrypt envelope)    | `beginLogin()` + `completeLogin()` (OIDC)       |
| `UtaUser.user_key`                        | `UtaSession.sub` (pairwise, stable per app)     |
| `getVersion(userKey) => string`           | `getEntitlement(accessToken) => Entitlement`    |
| RSA keys (`UTA_PRIVATE_KEY`, market key)  | OAuth client (`UTA_CLIENT_ID`/`UTA_CLIENT_SECRET`)|
| `UTA_APP_ID`                              | (gone — the client id identifies your app)      |
| `utaLaunchView` Express helper            | (gone — wire your own callback route)           |

Register an OAuth client and redirect URI in your usethatapp.com developer
dashboard to get `UTA_CLIENT_ID` / `UTA_CLIENT_SECRET`.

## Development

```bash
npm install
npm run build
npm test        # build + node:test suite
```

## Changelog

### 2.2.0 (2026-08-23)

**Added**

- **License Key API** (server-side, bring-your-own-auth MoR
  verification): `validateLicenseKey(key)`, `getOrder(ref)` for the
  `uta_order` checkout handback, and `regenerateLicenseKey(licenseId)`
  as the compromise kill switch — all authenticated with your app's
  client credentials, read from `UTA_CLIENT_SECRET` (or the file at
  `UTA_CLIENT_SECRET_PATH`) with no OIDC config needed. New
  `LicenseState` type and typed errors: `UtaNotFoundError` (with
  `.code`), `UtaOrderProcessingError`, `UtaLicenseCanceledError`.

- `UtaServiceNotEnabledError` (extends `UtaPermissionError`), thrown when
  the entitlement endpoint returns `403 service_not_enabled`: the app's
  developer has not enabled the Hosted sign-in add-on. Previously
  every entitlement 403 was labeled a missing `entitlements` scope; the
  new error names the actual fix (enable the add-on on the app's manage
  page). Existing `catch` blocks for `UtaPermissionError` match it
  unchanged.

### 2.1.0 (2026-08-11)

Thin support for selling your app from your own website (hosted purchase
links, buyer management page, public pricing API), plus OIDC hardening.
The new surface is additive, but the hardening tightens some previously
lax behavior — see *Security* and *Changed* below before upgrading.

**Added**

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

**Security**

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

**Changed**

- Request timeouts now cover the response body, not just the headers. A
  server that sends headers and then stalls fails after
  `UTA_REQUEST_TIMEOUT_SECONDS` instead of hanging indefinitely.
- `UTA_REQUEST_TIMEOUT_SECONDS` must be ≥ 1 and `UTA_CLOCK_SKEW_SECONDS`
  ≥ 0; out-of-range values raise `UtaConfigError` at config load.
  Previously `0` was accepted and aborted every request immediately.
- `getEntitlement` maps 429 to `UtaServerError` (retriable with backoff)
  instead of a generic non-retriable `UtaError`, matching the public
  pricing endpoints.

**Fixed**

- Gating guidance: the quickstart and `getPrices` docs now compare a
  price's `product_id` against `Entitlement.product_public_id`. The old
  wording pointed at `Entitlement.product_id`, whose legacy UUID makes
  the comparison false for every buyer.
- The example apps map `UtaServerError` to HTTP 502 rather than 400, so
  a provider outage is not reported as a client error.

### 2.0.0

Breaking rewrite onto standard OAuth2 / OpenID Connect. usethatapp.com is now
an OpenID Provider; the SDK is a framework-agnostic OIDC client.

**Removed**

- `getUser` / `getUserFromRequest` and the encrypted launch-envelope handling.
- `getVersion` / `clearVersionCache` and the process-local version cache.
- `utaLaunchView` Express helper — the SDK ships no framework-specific code.
- `UtaUser` (and its `user_key` / `version_hint`).
- RSA-key config (`UTA_PRIVATE_KEY[_PATH]`, `UTA_MARKET_PUBLIC_KEY[_PATH]`)
  and `UTA_APP_ID`.

**Added**

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

**Changed**

- One runtime dependency: `jose`. Identity is a pairwise, per-app pseudonymous
  `sub` — stable within your app, uncorrelatable across apps.

### 1.0.0

Breaking rewrite for the (now superseded) webhook-based launch-envelope handoff.

## License

MIT — see [LICENSE](./LICENSE).
