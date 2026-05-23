// Fastify launch endpoint. Fastify doesn't ship with a url-encoded
// body parser; `@fastify/formbody` adds support for what the
// marketplace posts.

import Fastify from "fastify";
import formbody from "@fastify/formbody";

import { getUser, getVersion, UtaError } from "usethatapp";

export async function buildApp() {
  const app = Fastify({ logger: false });
  await app.register(formbody);

  app.post("/launch", async (req, reply) => {
    const payload = req.body?.uta_payload;
    try {
      const user = getUser(payload);
      const version = await getVersion(user.user_key);
      return { user_key: user.user_key, version };
    } catch (e) {
      if (e instanceof UtaError) {
        reply.code(400);
        return { error: e.message };
      }
      throw e;
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 3000);
  const app = await buildApp();
  await app.listen({ port, host: "127.0.0.1" });
  console.log(`fastify-min listening on http://127.0.0.1:${port}`);
}
