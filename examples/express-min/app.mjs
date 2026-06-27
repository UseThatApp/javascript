// Minimal Express app: UseThatApp OIDC login + entitlement (docs only).
// The SDK ships no framework code — this shows the three bits you wire
// yourself: read callback params, store flowState in the session, redirect.
//
//   npm install usethatapp express express-session
//   export UTA_CLIENT_ID=... UTA_CLIENT_SECRET=... UTA_REDIRECT_URI=http://localhost:3000/callback
//   node app.mjs

import express from "express";
import session from "express-session";

import { beginLogin, completeLogin, getEntitlement, logoutUrl, UtaError, UtaTokenError } from "usethatapp";

export function createApp() {
  const app = express();
  app.use(session({ secret: process.env.SESSION_SECRET ?? "dev-only", resave: false, saveUninitialized: true }));

  app.get("/login", async (req, res, next) => {
    try {
      const { authorizationUrl, flowState } = await beginLogin();
      req.session.utaFlow = flowState;
      res.redirect(authorizationUrl);
    } catch (e) { next(e); }
  });

  app.get("/callback", async (req, res) => {
    // On cancel/deny, OAuth redirects back with ?error=... and no code.
    if (req.query.error) {
      delete req.session.utaFlow;
      return res.redirect("/");
    }
    try {
      const s = await completeLogin({
        code: req.query.code,
        state: req.query.state,
        flowState: req.session.utaFlow,
      });
      delete req.session.utaFlow;
      req.session.utaSub = s.sub;
      req.session.utaAccessToken = s.access_token;
      req.session.utaIdToken = s.id_token;
      res.redirect("/");
    } catch (e) {
      const code = e instanceof UtaError ? 400 : 500;
      res.status(code).send(`login failed: ${e.message}`);
    }
  });

  app.get("/", async (req, res, next) => {
    const token = req.session.utaAccessToken;
    if (token) {
      try {
        const ent = await getEntitlement(token);
        return res.json({ sub: req.session.utaSub, entitlement: ent.raw });
      } catch (e) {
        if (!(e instanceof UtaTokenError)) return next(e);
        // Token revoked/expired (signed out of UseThatApp). Reconcile.
        delete req.session.utaAccessToken;
        delete req.session.utaSub;
        delete req.session.utaIdToken;
      }
    }
    res.send('<a href="/login">Log in with UseThatApp</a>');
  });

  app.get("/logout", async (req, res, next) => {
    try {
      // Don't clear the session yet — the user may choose "Stay signed in". A
      // real logout revokes the token, so the next getEntitlement (home) 401s
      // and we drop it then.
      const idToken = req.session.utaIdToken;
      res.redirect(await logoutUrl({ idToken, postLogoutRedirectUri: "http://localhost:3000/" }));
    } catch (e) { next(e); }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => {
    console.log(`express-min listening on http://127.0.0.1:${port}`);
  });
}
