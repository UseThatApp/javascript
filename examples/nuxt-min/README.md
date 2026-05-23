# nuxt-min

Nuxt 3 server route for the launch webhook, in
`server/api/launch.post.mjs`. Nuxt's server runtime is h3, so this
exact file also works in any standalone h3 app — that's how the test
suite exercises it.

## Drop-in usage

Copy the `server/api/launch.post.mjs` file into your Nuxt 3 project at
the same path. Set the env vars:

```
UTA_APP_ID=...
UTA_PRIVATE_KEY=...
```

Nuxt automatically routes `server/api/launch.post.mjs` to `POST /api/launch`.

## Vue on top

A typical full flow:

1. Marketplace POSTs the envelope to `/api/launch` (this handler
   verifies + responds).
2. You persist `user_key` in a server-side session (Nuxt's
   `useStorage`, a cookie, etc.).
3. Your Vue components call a second server route that wraps
   `getVersion(user_key)` to render tier-specific UI.
