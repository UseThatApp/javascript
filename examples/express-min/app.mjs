// Express launch endpoint using the bundled `utaLaunchView` helper.
// The helper enforces POST-only, returns 400 on bad envelopes, and
// attaches the verified `UtaUser` to `req.utaUser`.

import express from "express";

import { getVersion, utaLaunchView } from "usethatapp";

export function createApp() {
  const app = express();
  app.use(express.urlencoded({ extended: false })); // marketplace posts form data
  app.use(express.json());

  app.post(
    "/launch",
    utaLaunchView(async (req, user, res) => {
      const version = await getVersion(user.user_key);
      res.json({ user_key: user.user_key, version });
    }),
  );

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => {
    console.log(`express-min listening on http://127.0.0.1:${port}`);
  });
}
