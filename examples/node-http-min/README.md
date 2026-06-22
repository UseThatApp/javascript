# node-http-min

Smallest possible OIDC login flow — only Node's built-in `http` module, no
web framework, no dependencies beyond `usethatapp`. Uses a toy in-memory
cookie session to show the three bits you wire yourself: read callback
params, store `flowState`, redirect.

## Run

```bash
npm install usethatapp
export UTA_CLIENT_ID=... UTA_CLIENT_SECRET=...
export UTA_REDIRECT_URI=http://localhost:3000/callback
node examples/node-http-min/app.mjs
```

Routes: `/login`, `/callback`, `/logout`, and `/` (shows the entitlement).
The in-memory session is for illustration only — use a real session store in
production.
