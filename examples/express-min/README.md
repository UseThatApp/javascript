# express-min

Express OIDC login / callback / logout using the framework-agnostic SDK.
The SDK ships no Express-specific code — this wires the three bits yourself:
read callback params (`req.query`), store `flowState` in `req.session`, redirect.

## Run

```bash
npm install usethatapp express express-session
export UTA_CLIENT_ID=... UTA_CLIENT_SECRET=...
export UTA_REDIRECT_URI=http://localhost:3000/callback
node examples/express-min/app.mjs
```

Routes: `/login` starts the flow, `/callback` completes it, `/` shows the
entitlement, `/logout` ends the session. Identity is `session.sub` — a
pairwise pseudonymous id (no PII); key your user records off it.
