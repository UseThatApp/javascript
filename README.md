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
  UtaTokenError, UtaPermissionError, UtaServerError,
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
if (ent.entitled && ent.product_id === "...") { /* ... */ }
```

Runnable demos live under [`examples/`](./examples/) — documentation only;
nothing framework-specific ships in the package.

## Error mapping

`getEntitlement` maps status codes to typed errors:

| Status | Error                | Meaning                                        |
|--------|----------------------|------------------------------------------------|
| 401    | `UtaTokenError`      | Access token invalid/expired — re-auth/refresh.|
| 403    | `UtaPermissionError` | Token lacks the `entitlements` scope.          |
| 400    | `UtaError`           | Client not linked to an app (misconfig).       |
| 5xx    | `UtaServerError`     | Retriable with backoff.                        |

All inherit from `UtaError` — catch that for a single `catch` clause.

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

### 2.1.0 (2026-07-30)

Purely additive — nothing existing changed. Thin support for selling your
app from your own website (hosted purchase links, buyer management page,
public pricing API).

**Added**

- `purchaseUrl(priceId, { next, ref, email })` — pure builder for the hosted
  checkout URL of a price.
- `manageUrl({ next })` — pure builder for the buyer's subscription-management
  page URL for your app.
- `getAppInfo()` → `AppInfo` — the app's public listing info (anonymous, no
  auth).
- `getPrices()` → `AppPrices` — the app's public price list (anonymous, no
  auth); each `UtaPrice` carries a ready-made `buy_url` and a `product_id`
  matching the entitlement endpoint's.
- New types: `AppInfo`, `AppPrices`, `UtaPrice`.
- `Entitlement.product_public_id` — the opaque public product identifier
  (`prod_…`) matching `UtaPrice.product_id` from the pricing API. New
  integrations should gate on it; `Entitlement.product_id` currently
  carries a legacy UUID and will converge on the same `prod_…` value.

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
