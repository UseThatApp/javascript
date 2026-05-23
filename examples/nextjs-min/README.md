# nextjs-min

Next.js App Router route handler for the launch webhook. The whole
integration is one file: `app/api/launch/route.mjs`.

## Drop-in usage

Copy `app/api/launch/route.mjs` into your Next.js project at the same
path (you can drop the `.mjs` and use `.js` or `.ts` to match the rest
of your code). Make sure these are set in `.env.local`:

```
UTA_APP_ID=...
UTA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
```

## Why "min" doesn't include Next.js itself

Next.js App Router route handlers receive a standard `Request` and
return a standard `Response`. The example file deliberately doesn't
import anything from `"next"` — it can be unit-tested by calling
`POST(new Request(...))` directly with no Next.js runtime.

## React on top

A typical full flow:

1. Marketplace POSTs the envelope to `/api/launch` (this file
   verifies + responds).
2. You persist `user_key` in a server-side session.
3. Your React Server Components and Client Components call
   `getVersion(user_key)` (or a `useEffect` that hits another API
   route) to render tier-specific UI.
