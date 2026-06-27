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
  configure, resetConfig,
  type UtaSession, type Entitlement, type UtaFlowState,
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
