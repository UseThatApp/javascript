// Next.js App Router route handler at /api/launch.
//
// Next.js App Router handlers receive a standard `Request` and return
// a standard `Response`, so this file works in any environment that
// implements those globals — including Node 18+ on its own. Nothing
// in this file imports from "next".

import { getUser, getVersion, UtaError } from "usethatapp";

export async function POST(request) {
  let payload;
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = await request.json();
    payload = body?.uta_payload;
  } else {
    const form = await request.formData();
    payload = form.get("uta_payload");
  }

  try {
    const user = getUser(payload);
    const version = await getVersion(user.user_key);
    return Response.json({ user_key: user.user_key, version });
  } catch (e) {
    if (e instanceof UtaError) {
      return new Response(`invalid launch payload: ${e.message}`, { status: 400 });
    }
    throw e;
  }
}
