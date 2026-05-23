# node-http-min

Smallest possible launch endpoint — uses only Node's built-in `http`
module. No web framework, no dependencies beyond `usethatapp`.

Demonstrates `getUser(payload)` + `getVersion(user_key)`.

## Run

```bash
export UTA_APP_ID=...
export UTA_PRIVATE_KEY="$(cat my_private.pem)"
node examples/node-http-min/app.mjs
```

POSTs to `http://127.0.0.1:3000/launch` are verified; the response is
`{ user_key, version }`.
