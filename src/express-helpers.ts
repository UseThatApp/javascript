import { getUserFromRequest, type UtaRequestLike } from "./client.js";
import { UtaError } from "./errors.js";
import type { UtaUser } from "./types.js";

/** Minimal Express/Connect-style response shape used by the helper. */
export interface UtaResponseLike {
  status(code: number): UtaResponseLike;
  setHeader(name: string, value: string): unknown;
  send(body: string): unknown;
  end(...args: unknown[]): unknown;
}

export interface UtaLaunchRequest extends UtaRequestLike {
  method?: string;
  utaUser?: UtaUser;
}

export type UtaLaunchHandler = (
  req: UtaLaunchRequest,
  utaUser: UtaUser,
  res: UtaResponseLike,
  next?: (err?: unknown) => void,
) => unknown | Promise<unknown>;

export type UtaLaunchMiddleware = (
  req: UtaLaunchRequest,
  res: UtaResponseLike,
  next?: (err?: unknown) => void,
) => unknown | Promise<unknown>;

/**
 * Wrap an Express-style handler so it only fires for verified launch
 * POSTs from usethatapp.com.
 *
 *   * Only POST is accepted; other methods return 405.
 *   * Body parsing must already be installed (e.g. `express.json()` or
 *     `express.urlencoded()`); the helper reads `req.body.uta_payload`.
 *   * Any `UtaError` results in 400 with a short reason and a warning
 *     log entry (via `console.warn`).
 *   * On success, the verified `UtaUser` is attached to `req.utaUser`
 *     and passed as the second positional argument to your handler.
 *
 * Note: there's no CSRF protection to disable here — Express has no
 * default CSRF middleware. The envelope's signature is the auth.
 */
export function utaLaunchView(handler: UtaLaunchHandler): UtaLaunchMiddleware {
  return async (req, res, next) => {
    if (req.method !== undefined && req.method !== "POST") {
      res.setHeader("Allow", "POST");
      res.status(405).end();
      return;
    }
    let user: UtaUser;
    try {
      user = getUserFromRequest(req);
    } catch (e) {
      if (e instanceof UtaError) {
        console.warn(`utaLaunchView: rejecting launch: ${e.message}`);
        res.status(400).send(`invalid launch payload: ${e.message}`);
        return;
      }
      if (typeof next === "function") {
        next(e);
        return;
      }
      throw e;
    }
    req.utaUser = user;
    return handler(req, user, res, next);
  };
}
