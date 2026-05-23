# express-min

Express launch endpoint using `utaLaunchView`.

## Run

```bash
npm install express
export UTA_APP_ID=...
export UTA_PRIVATE_KEY="$(cat my_private.pem)"
node examples/express-min/app.mjs
```

`utaLaunchView`:

- Restricts the route to `POST` (returns 405 otherwise).
- Returns 400 with a short reason on any envelope failure.
- Attaches the verified `UtaUser` to `req.utaUser` *and* passes it as
  the second positional argument to your handler.
