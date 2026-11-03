// Minimal Express app: sell with UseThatApp, verify with license keys (docs only).
// Your app keeps its own login; UseThatApp only sells. The buyer clicks Buy,
// pays on usethatapp.com, and returns to /thanks?uta_order=... where the key
// is stored on the signed-in user. /pro is a paid feature gated on that key.
//
//   npm install usethatapp express express-session
//   export UTA_CLIENT_ID=... UTA_CLIENT_SECRET=...
//   export UTA_PRICE_ID=prc_... UTA_PRO_PRODUCT=prod_...
//   node app.mjs
//
// Users live in memory so the example stays short.

import express from "express";
import session from "express-session";

import { getOrder, purchaseUrl, validateLicenseKey, UtaError, UtaOrderProcessingError } from "usethatapp";

const PRICE_ID = process.env.UTA_PRICE_ID;       // prc_… from getPrices() or the dashboard
const PRO_PRODUCT = process.env.UTA_PRO_PRODUCT; // prod_… the price belongs to
const BASE = "http://localhost:3000";            // loopback is allowed as `next` in development
if (!PRICE_ID || !PRO_PRODUCT) throw new Error("Set UTA_PRICE_ID and UTA_PRO_PRODUCT.");

export function createApp({ users = new Map() } = {}) {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(session({ secret: process.env.SESSION_SECRET ?? "dev-only", resave: false, saveUninitialized: false }));

  const currentUser = (req) => users.get(req.session.user);

  // Stand-in for YOUR auth (Auth0, Clerk, Passport, ...).
  app.get("/login", (req, res) => {
    res.send('<form method="post"><input name="name" placeholder="your name"><button>Sign in</button></form>');
  });
  app.post("/login", (req, res) => {
    const name = req.body.name;
    if (!users.has(name)) users.set(name, { licenseKey: null, licenseId: null });
    req.session.user = name;
    const after = req.session.afterLogin ?? "/";
    delete req.session.afterLogin;
    res.redirect(after);
  });

  app.get("/", (req, res) => {
    if (!currentUser(req)) return res.redirect("/login");
    const buy = purchaseUrl(PRICE_ID, { next: `${BASE}/thanks` });
    res.send(`<a href="${buy}">Buy Pro</a> · <a href="/pro">Pro feature</a>`);
  });

  app.get("/thanks", async (req, res) => {
    const ref = req.query.uta_order;
    if (!ref) return res.redirect("/");
    const user = currentUser(req);
    if (!user) {
      // Never drop the ref: finish linking it after the user signs in.
      req.session.afterLogin = req.originalUrl;
      return res.redirect("/login");
    }
    try {
      const order = await getOrder(ref);
      user.licenseKey = order.license_key;
      user.licenseId = order.license_id;
      res.redirect("/pro");
    } catch (e) {
      // Paid, key not stored yet. Reload shortly.
      if (e instanceof UtaOrderProcessingError) return res.send('<meta http-equiv="refresh" content="2">Finishing up your purchase…');
      if (e instanceof UtaError) return res.status(502).send("Could not confirm the purchase.");
      throw e;
    }
  });

  app.get("/pro", async (req, res) => {
    const user = currentUser(req);
    if (!user) return res.redirect("/login");
    if (user.licenseKey) {
      const state = await validateLicenseKey(user.licenseKey);
      if (state.entitled && state.product_public_id === PRO_PRODUCT) return res.send("Welcome to Pro.");
    }
    res.redirect("/");
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createApp().listen(3000, () => console.log(`listening on ${BASE}`));
}
