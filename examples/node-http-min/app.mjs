// Minimal plain node:http app: UseThatApp OIDC login + entitlement (docs only).
// No framework, no session library — a tiny in-memory cookie session shows the
// three bits you wire yourself: read callback params, store flowState, redirect.
//
//   npm install usethatapp
//   export UTA_CLIENT_ID=... UTA_CLIENT_SECRET=... UTA_REDIRECT_URI=http://localhost:3000/callback
//   node app.mjs

import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

import { beginLogin, completeLogin, getEntitlement, logoutUrl, UtaError } from "usethatapp";

// Toy server-side session store keyed by a cookie. Use a real session in prod.
const sessions = new Map();

function getSession(req, res) {
  const sid = (req.headers.cookie ?? "").match(/sid=([^;]+)/)?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  const id = randomBytes(16).toString("hex");
  const data = {};
  sessions.set(id, data);
  res.setHeader("Set-Cookie", `sid=${id}; HttpOnly; Path=/`);
  return data;
}

export function createApp() {
  return createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const sess = getSession(req, res);
    try {
      if (url.pathname === "/login") {
        const { authorizationUrl, flowState } = await beginLogin();
        sess.utaFlow = flowState;
        res.writeHead(302, { Location: authorizationUrl }).end();
      } else if (url.pathname === "/callback") {
        const s = await completeLogin({
          code: url.searchParams.get("code"),
          state: url.searchParams.get("state"),
          flowState: sess.utaFlow,
        });
        delete sess.utaFlow;
        sess.utaSub = s.sub;
        sess.utaAccessToken = s.access_token;
        sess.utaIdToken = s.id_token;
        res.writeHead(302, { Location: "/" }).end();
      } else if (url.pathname === "/logout") {
        const idToken = sess.utaIdToken;
        for (const k of Object.keys(sess)) delete sess[k];
        res.writeHead(302, { Location: await logoutUrl({ idToken }) }).end();
      } else {
        if (!sess.utaAccessToken) {
          res.end('<a href="/login">Log in with UseThatApp</a>');
          return;
        }
        const ent = await getEntitlement(sess.utaAccessToken);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ sub: sess.utaSub, entitlement: ent.raw }));
      }
    } catch (e) {
      res.writeHead(e instanceof UtaError ? 400 : 500).end(`error: ${e.message}`);
    }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => {
    console.log(`node-http-min listening on http://127.0.0.1:${port}`);
  });
}
