# usethatapp

JavaScript/TypeScript SDK for [usethatapp.com](https://usethatapp.com).
Verifies the encrypted+signed *launch envelope* the marketplace POSTs to
your app and lets you pull the user's current license tier on demand.

**Framework-friendly.** Ships a thin Express helper (`utaLaunchView`) on
top of a framework-agnostic core (`getUser`, `getVersion`).
No runtime dependencies — uses Node's built-in `crypto` and `fetch`.

> **v1.0 is a breaking rewrite.** The old browser-side `usethatapp.js`
> / `requestAccessLevel()` / iframe handshake has been removed. See
> [CHANGELOG.md](#changelog) below for migration notes.

**Requires:** Node.js 18+ (Node 20+ recommended; uses global `fetch`).

## How it works

usethatapp.com uses a two-phase, license-centric handoff:

1. **Launch (one-way push).** When a user clicks *Launch app* on
   usethatapp.com, the marketplace POSTs an encrypted+signed envelope
   to your app's URL. The envelope carries an opaque `user_key`. Your
   app verifies + decrypts it, persists `user_key` against its own
   session, and renders your UI.
2. **Query (server-to-server pull).** Whenever your app needs the
   user's current license tier, it POSTs a signed request to
   `https://usethatapp.com/licensing/getversion/` with the `user_key`
   and gets back the live product name (or `null`).

Envelope crypto: `RSA-OAEP-SHA256 + AES-256-GCM + RSA-PSS-SHA256`. The
PSS signature covers `ek || iv || ct`.

## Install

```bash
npm install usethatapp
```

## Settings

The SDK reads from `process.env` by default. You can also override any
setting programmatically with `configure({...})`.

| Name                          | Required | Purpose                                                                  |
|-------------------------------|----------|--------------------------------------------------------------------------|
| `UTA_APP_ID`                  | yes      | Your app's UUID on usethatapp.com.                                       |
| `UTA_PRIVATE_KEY`             | yes†     | Your RSA-2048 private key, PEM string (literal `\n` escapes supported).  |
| `UTA_PRIVATE_KEY_PATH`        | yes†     | Filesystem path to a PEM file containing the private key. †Set this *or* `UTA_PRIVATE_KEY`. |
| `UTA_MARKET_PUBLIC_KEY`       | yes*     | Marketplace public key, PEM string. *A production default is bundled.   |
| `UTA_MARKET_PUBLIC_KEY_PATH`  | no       | Filesystem path to a PEM file containing the marketplace public key (alternative to `UTA_MARKET_PUBLIC_KEY`). |
| `UTA_API_URL`                 | no       | Defaults to `https://usethatapp.com`.                                    |
| `UTA_CLOCK_SKEW_SECONDS`      | no       | Defaults to `60`.                                                        |
| `UTA_REQUEST_TIMEOUT_SECONDS` | no       | Defaults to `10`.                                                        |

The `*_PATH` variants are intended for hosting providers that mount
secret files into the container (Render Secret Files, Fly.io volumes,
Kubernetes secret volumes, etc.). The SDK reads the file at boot via
`fs.readFileSync`. If both the direct setting and the path setting
are provided for the same key, the direct value wins.

## Public API

```ts
import {
  getUser,               // framework-agnostic: takes the raw uta_payload string/object
  getUserFromRequest,    // Express/Connect-style helper (reads req.body.uta_payload)
  getVersion,            // signed server-to-server license-tier lookup
  clearVersionCache,
  utaLaunchView,         // Express handler wrapper
  configure, resetConfig,
  // types & errors:
  type UtaUser,
  UtaError, UtaSignatureError, UtaPayloadExpiredError,
  UtaAppMismatchError, UtaBadRequestError, UtaSessionRevokedError,
  UtaUnknownSessionError, UtaServerError, UtaConfigError,
} from "usethatapp";
```

`UtaUser` carries only the opaque `user_key` — no PII. Persist it
against your own session and pass it to `getVersion` whenever you need
the live license tier.

```ts
interface UtaUser {
  readonly user_key: string;
  readonly app_id: string;
  readonly issued_at: number;   // unix seconds
  readonly expires_at: number;  // unix seconds
  readonly version_hint: string | null;
}
```

## Quickstart — Express

```js
import express from "express";
import { utaLaunchView, getVersion } from "usethatapp";

const app = express();
app.use(express.urlencoded({ extended: false }));

// Launch endpoint — POST'd by usethatapp.com.
app.post("/launch", utaLaunchView(async (req, utaUser, res) => {
  req.session.utaUserKey = utaUser.user_key;          // persist
  const version = await getVersion(utaUser.user_key); // live tier
  res.send(`Welcome — your tier is ${version ?? "(none)"}.`);
}));

// Anywhere else, look up the live tier on demand.
app.get("/api/whatever", async (req, res) => {
  const version = await getVersion(req.session.utaUserKey);
  res.json({ version });
});

app.listen(3000);
```

## Quickstart — any Node framework

```js
import { getUser, getVersion, UtaError } from "usethatapp";

// In your POST handler — however your framework spells body parsing:
try {
  const utaUser = getUser(req.body.uta_payload);
  session.utaUserKey = utaUser.user_key;
} catch (e) {
  if (e instanceof UtaError) return badRequest(e.message);
  throw e;
}

// Later, anywhere in your app:
const version = await getVersion(session.utaUserKey); // string | null
```

> `utaUser.version_hint` is **not** the source of truth. Use it only
> for first paint. The authoritative value comes from
> `getVersion(user_key)`.

## Framework examples

Runnable single-file examples for each major Node framework live under
[`examples/`](./examples/):

- [`examples/node-http-min/`](./examples/node-http-min/) — plain
  `node:http`, no framework.
- [`examples/express-min/`](./examples/express-min/) — Express +
  `utaLaunchView`.
- [`examples/fastify-min/`](./examples/fastify-min/) — Fastify +
  `@fastify/formbody`.
- [`examples/nextjs-min/`](./examples/nextjs-min/) — Next.js App
  Router route handler (covers React projects).
- [`examples/nuxt-min/`](./examples/nuxt-min/) — Nuxt 3 server route
  via h3 (covers Vue projects).

Each is exercised end-to-end by
[`scripts/example-tests.mjs`](./scripts/example-tests.mjs) — `npm run
test:examples`.

## Error mapping

`getVersion` maps server status codes to typed errors:

| Status | Error                    | Meaning                                |
|--------|--------------------------|----------------------------------------|
| 400    | `UtaBadRequestError`     | Bad JSON / ts outside window / replay. |
| 401    | `UtaSignatureError`      | Signature verification failed.         |
| 403    | `UtaSessionRevokedError` | Treat as "user logged out".            |
| 404    | `UtaUnknownSessionError` | Unknown `user_key` or `app_id`.        |
| 5xx    | `UtaServerError`         | Retriable with backoff.                |

All inherit from `UtaError` — catch that for a single `catch` clause.

## Programmatic configuration

For tests or apps that don't read from `process.env`:

```js
import { configure } from "usethatapp";
import { readFileSync } from "node:fs";

configure({
  app_id: "11111111-2222-3333-4444-555555555555",
  private_key: readFileSync("./my_private.pem", "utf8"),
  api_url: "https://staging.usethatapp.com",
});
```

## Development

```bash
npm install
npm run build
npm test                # build + compat tests + example tests
npm run test:compat     # round-trip tests + HTTP mock for getVersion
npm run test:examples   # exercises every framework example end-to-end
```

## Changelog

### 1.0.0

Breaking rewrite for the new usethatapp.com webhook-based handoff.

**Removed**

- `usethatapp.js` integration, `requestAccessLevel()` JS bridge, and all
  iframe / `postMessage` handling.
- The old `webapps` subpath export and the
  `getVersion(envelope, publicKeyPath, privateKeyPath)` signature.
- The `Keys`, `decryptMessage`, `verifySignature` low-level exports —
  PEM key handling is now internal to `config`.

**Added**

- `getUser(payload)` — verify + decrypt the launch envelope POSTed by
  the marketplace. Framework-agnostic; takes the raw `uta_payload`
  string or already-parsed object.
- `getUserFromRequest(req)` — Express/Connect-style helper that pulls
  `uta_payload` from `req.body` and forwards to `getUser`.
- `getVersion(userKey)` — signed server-to-server POST to
  `https://usethatapp.com/licensing/getversion/`, returning the current
  product name or `null`. Honors a process-local TTL cache.
- `utaLaunchView(handler)` Express helper (POST-only, 400 on bad
  envelope, attaches `req.utaUser`).
- `UtaUser` interface (`user_key`, `app_id`, `issued_at`, `expires_at`,
  `version_hint`).
- Hybrid envelope crypto:
  `RSA-OAEP-SHA256 + AES-256-GCM + RSA-PSS-SHA256`. PSS signature now
  covers `ek || iv || ct` (not the plaintext).
- Typed error hierarchy under `UtaError`. Every failure mode (local
  validation + each HTTP status) maps to a specific subclass.
- `configure({...})` / `resetConfig()` for programmatic settings.
- `UTA_PRIVATE_KEY_PATH` and `UTA_MARKET_PUBLIC_KEY_PATH` env vars
  (and `private_key_path` / `market_public_key_path` programmatic
  overrides) for reading PEM contents from a file at boot — intended
  for hosting providers that mount secret files into the container.
  Direct values take precedence when both are set.

### 0.2.0

- Breaking change: `getVersion()` expected the full `Envelope` from
  `requestAccessLevel()` instead of the inner `ProductMessage`.

### 0.1.1

- Initial release.

## License

MIT — see [LICENSE](./LICENSE).
