// Nuxt 3 server route at /api/launch (POST). Nuxt's server runtime is
// h3, which provides `defineEventHandler` and `readBody`. The exact
// same file works in a standalone h3 app — see the test runner.

import {
  defineEventHandler,
  getHeader,
  readBody,
  setResponseStatus,
} from "h3";

import { getUser, getVersion, UtaError } from "usethatapp";

export default defineEventHandler(async (event) => {
  // h3's readBody parses based on Content-Type. The marketplace POSTs
  // application/x-www-form-urlencoded; readBody yields a plain object.
  const contentType = getHeader(event, "content-type") ?? "";
  const body = await readBody(event);
  const payload =
    typeof body === "string" && contentType.includes("application/json")
      ? JSON.parse(body)?.uta_payload
      : body?.uta_payload;

  try {
    const user = getUser(payload);
    const version = await getVersion(user.user_key);
    return { user_key: user.user_key, version };
  } catch (e) {
    if (e instanceof UtaError) {
      setResponseStatus(event, 400);
      return { error: e.message };
    }
    throw e;
  }
});
