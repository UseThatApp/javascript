# usethatapp

JavaScript/TypeScript SDK for [UseThatApp](https://www.usethatapp.com), the
merchant of record for web apps. You put Buy buttons on your own website;
UseThatApp runs checkout, charges the card, collects and remits tax, handles
refunds, and pays you through Stripe. This SDK lets your server show live
prices, build checkout links, and check what each customer bought.

- Docs: <https://docs.usethatapp.com>
- AI agents: read <https://docs.usethatapp.com/llms-full.txt> (the whole
  site as one Markdown file) and follow its "Rules for AI agents".

## Install

```bash
npm install usethatapp
```

Node.js 18+ (global `fetch` and WebCrypto). One runtime dependency,
[`jose`](https://github.com/panva/jose). The SDK is **server-side only**: it
holds your client secret, so never bundle it into a browser app or ship it
inside a desktop app. A single-page app calls its own backend, which calls
the SDK. The SDK never touches your web framework — it takes and returns
plain values, and you wire it into your routes.

## Configure

Settings come from `process.env`; `configure({...})` overrides them in code.

| Variable | Needed for |
|---|---|
| `UTA_CLIENT_ID` | Everything except `purchaseUrl` |
| `UTA_CLIENT_SECRET` (or `UTA_CLIENT_SECRET_PATH` for a mounted file) | License keys, Hosted sign-in |
| `UTA_REDIRECT_URI` | Hosted sign-in only |
| `UTA_SCOPES`, `UTA_API_URL`, `UTA_ISSUER`, `UTA_REQUEST_TIMEOUT_SECONDS`, `UTA_CLOCK_SKEW_SECONDS` | Optional; defaults point at production |

The client id and secret are on your app's *Manage → Integration* page.
The secret is shown once; keep it in your host's secret store.

## Verify purchases with license keys (the default)

Each purchase creates one license key. When checkout finishes, the buyer
returns to your buy link's `next` URL with `?uta_order=…` appended. Your
server exchanges that once for the key, stores it on the user signed in to
*your* app, and validates it wherever you gate a paid feature. Your login
stays yours.

```js
import { getOrder, validateLicenseKey, UtaOrderProcessingError } from "usethatapp";

// Return route, e.g. /thanks?uta_order=...
let order;
try {
  order = await getOrder(req.query.uta_order);
} catch (e) {
  if (e instanceof UtaOrderProcessingError) return res.render("finishing-up"); // retry in a second or two
  throw e;
}
currentUser.licenseKey = order.license_key;
currentUser.licenseId = order.license_id;

// Any gate:
const state = await validateLicenseKey(currentUser.licenseKey);
if (state.entitled && state.product_public_id === "prod_<your-pro-id>") {
  // paid feature
}
```

- Gate on `entitled` and `product_public_id` (the plan's `prod_…` id;
  `product_id` holds the same value). Never on the plan's display name.
- A cancellation keeps `entitled: true` until `period_end`; the buyer paid
  for that period. Cache the answer for a session or up to a day, never past
  `period_end`.
- A buyer who already holds a plan is sent back to `next` with no
  `uta_order`; treat its absence as nothing to link.
- A canceled key returns `entitled: false`; it does not throw.
  `UtaNotFoundError` means the string was never a key for your app.
- A lost key is always visible on the buyer's manage page. Rotate only a
  leaked one: `regenerateLicenseKey(licenseId)` returns the new key once
  and kills the old one.

Response fields are snake_case, exactly as the API sends them. Walkthrough,
statuses and edge cases: <https://docs.usethatapp.com/license-keys>.

## Show prices and link to checkout

```js
import { getPrices, manageUrl, purchaseUrl } from "usethatapp";

const { prices, has_free_tier } = await getPrices();   // anonymous; needs only UTA_CLIENT_ID
for (const p of prices) {
  showPlan(p.product_name, p.amount, p.currency, p.frequency, p.buy_url);
}

purchaseUrl("prc_...", { next: "https://yourapp.example/thanks" });  // no network call
manageUrl({ next: "https://yourapp.example/account" });              // buyer's subscription page
```

Never hardcode prices: render them from `getPrices()` and use each price's
`buy_url`. `amount` is a decimal string (`"10.00"`); format it, don't
`parseFloat` it. `next` must be HTTPS on your app's registered domain
(loopback hosts such as `localhost` are accepted for local testing). Until
the seller is verified, the app is published and the product is active, a
buy link shows the buyer a "not available" page instead of checkout; it
answers 404 only for an unknown price id or an app whose sales UseThatApp
has suspended. Details: <https://docs.usethatapp.com/sell>.

## Hosted sign-in (optional add-on)

Only if your app has no accounts of its own: UseThatApp runs login over
OpenID Connect, and `getEntitlement` reports what the signed-in user bought.
The entitlement call needs the Hosted sign-in add-on, switched on in the
dashboard.

```js
import { beginLogin, completeLogin, getEntitlement } from "usethatapp";

const { authorizationUrl, flowState } = await beginLogin();      // /login: keep flowState in the session
const s = await completeLogin({ code, state, flowState });       // /callback
const ent = await getEntitlement(s.access_token);                // gate on ent.entitled + ent.product_public_id
```

Users are identified by `s.sub`, a pairwise pseudonymous id with no email or
name. Setup, sign-out and stack notes: <https://docs.usethatapp.com/hosted-sign-in>.

## Errors

Every error extends `UtaError`.

| Error | When |
|---|---|
| `UtaConfigError` | Missing settings, or the client id/secret was rejected |
| `UtaNotFoundError` (`.code`) | A key, order or license id never issued for your app |
| `UtaOrderProcessingError` | Order paid, key not stored yet: retry shortly |
| `UtaLicenseCanceledError` | Rotating a key whose license has ended |
| `UtaServerError` (`.retryAfter`) | Rate limited (429) or a server error: back off and retry |
| `UtaTokenError`, `UtaPermissionError`, `UtaServiceNotEnabledError`, `UtaAuthError`, `UtaDiscoveryError` | Hosted sign-in only |

Full table: <https://docs.usethatapp.com/rest-api#errors>.

## API

| Function | Returns |
|---|---|
| `getOrder(ref)` / `validateLicenseKey(key)` / `regenerateLicenseKey(licenseId)` | `LicenseState` |
| `getPrices()` | `AppPrices` (with `UtaPrice` entries) |
| `getAppInfo()` | `AppInfo` |
| `purchaseUrl(priceId, { next, ref, email })` / `manageUrl({ next })` | `string` (no network) |
| `beginLogin()` / `completeLogin({ code, state, flowState })` / `refresh(refreshToken)` | `{ authorizationUrl, flowState }` / `UtaSession` |
| `getEntitlement(accessToken)` | `Entitlement` |
| `userinfo(accessToken)` / `logoutUrl({ idToken, postLogoutRedirectUri })` | `{ sub }` / `string` |
| `configure({...})` / `loadConfig()` / `resetConfig()` | Configuration |

Every call is plain HTTPS underneath, documented at
<https://docs.usethatapp.com/rest-api>. TypeScript types ship with the
package.

## Examples

[`examples/`](./examples/) holds runnable apps: `license-keys-express` (the
default integration) and Hosted sign-in apps for Express and plain Node
`http`.

## Development

```bash
npm install
npm test        # build + node:test suite
```

## Changelog and license

[CHANGELOG.md](./CHANGELOG.md), including how to migrate from 1.x. MIT —
see [LICENSE](./LICENSE).
