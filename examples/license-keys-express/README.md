# license-keys-express

The default UseThatApp integration in Express: your own login, a buy link,
a `/thanks` route that exchanges `uta_order` for the buyer's license key,
and a `/pro` route gated on `validateLicenseKey`. No UseThatApp sign-in.

## Run

```bash
npm install usethatapp express express-session
export UTA_CLIENT_ID=... UTA_CLIENT_SECRET=...
export UTA_PRICE_ID=prc_... UTA_PRO_PRODUCT=prod_...
node examples/license-keys-express/app.mjs
```

Sign in with any name, click **Buy Pro**, and finish checkout; you return to
`/thanks` and land on `/pro`. Opening your own buy link while signed in to
usethatapp.com as the app's developer runs a no-charge walkthrough, which
creates no license key, so test this flow with one real purchase from a
second account.
