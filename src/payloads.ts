import {
  constants,
  createCipheriv,
  createDecipheriv,
  publicEncrypt,
  privateDecrypt,
  randomBytes,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import { UtaError, UtaSignatureError } from "./errors.js";

export const ENVELOPE_VERSION = 1;
export const ALG_LABEL = "RSA-OAEP-SHA256+AES-256-GCM+RSA-PSS-SHA256";

const REQUIRED_ENVELOPE_FIELDS = ["v", "alg", "ek", "iv", "ct", "signature"] as const;

export interface Envelope {
  v: number;
  alg: string;
  ek: string;
  iv: string;
  ct: string;
  signature: string;
}

export interface InnerPayload {
  kind: string;
  user_key: string;
  app_id: string;
  iat: number;
  exp: number;
  nonce: string;
  version_hint?: string;
}

const HEX_RE = /^[0-9a-fA-F]*$/;

function fromHex(name: string, value: unknown): Buffer {
  if (typeof value !== "string") {
    throw new UtaError(`envelope field '${name}' must be a hex string`);
  }
  if (value.length % 2 !== 0 || !HEX_RE.test(value)) {
    throw new UtaError(`envelope field '${name}' is not valid hex`);
  }
  return Buffer.from(value, "hex");
}

/**
 * Verify + decrypt + JSON-parse a launch envelope.
 *
 * Verification order:
 *   1. JSON-decode the envelope and check required fields.
 *   2. Hex-decode `ek`, `iv`, `ct`, `signature`.
 *   3. PSS-verify `signature` over `ek || iv || ct` with `marketPublicKey`.
 *   4. RSA-OAEP-unwrap `ek` with `developerPrivateKey` to obtain the
 *      32-byte AES key.
 *   5. AES-256-GCM decrypt `ct` with `aad = ek || iv`.
 *   6. JSON-parse the plaintext and return the object.
 */
export function unpackPayload(
  envelope: string | Record<string, unknown>,
  opts: { developerPrivateKey: KeyObject; marketPublicKey: KeyObject },
): InnerPayload {
  // 1. JSON decode
  let env: Record<string, unknown>;
  if (typeof envelope === "string") {
    try {
      const parsed = JSON.parse(envelope);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new UtaError("envelope JSON is not an object");
      }
      env = parsed as Record<string, unknown>;
    } catch (e) {
      if (e instanceof UtaError) throw e;
      const err = e instanceof Error ? e.message : String(e);
      throw new UtaError(`envelope is not valid JSON: ${err}`);
    }
  } else if (envelope !== null && typeof envelope === "object") {
    env = envelope as Record<string, unknown>;
  } else {
    throw new UtaError(
      `envelope must be a JSON string or object, got ${
        envelope === null ? "null" : typeof envelope
      }. If you have an Express/Connect-style request object, call `
        + `getUserFromRequest(req) instead of getUser(req).`,
    );
  }

  // Heuristic: catch the most common migration mistake — calling
  // getUser(req) instead of getUserFromRequest(req). A genuine
  // envelope has none of these request-shaped fields, so when we see
  // them combined with the absence of any envelope fields, it's
  // overwhelmingly a wrong-API-call rather than a malformed envelope.
  const hasNoEnvelopeFields = !REQUIRED_ENVELOPE_FIELDS.some((f) => f in env);
  const looksLikeRequest =
    "body" in env || "headers" in env || "method" in env;
  if (hasNoEnvelopeFields && looksLikeRequest) {
    throw new UtaError(
      "envelope looks like an HTTP request object, not a launch "
        + "envelope. Call getUserFromRequest(req) instead of getUser(req), "
        + "or pass req.body.uta_payload to getUser().",
    );
  }

  // Field presence
  const missing = REQUIRED_ENVELOPE_FIELDS.filter((f) => !(f in env));
  if (missing.length > 0) {
    throw new UtaError(`envelope missing fields: ${missing.join(", ")}`);
  }

  if (env.v !== ENVELOPE_VERSION) {
    throw new UtaError(`unsupported envelope version: ${JSON.stringify(env.v)}`);
  }
  if (env.alg !== ALG_LABEL) {
    throw new UtaError(`unsupported envelope alg: ${JSON.stringify(env.alg)}`);
  }

  // 2. hex decode
  const ek = fromHex("ek", env.ek);
  const iv = fromHex("iv", env.iv);
  const ct = fromHex("ct", env.ct);
  const signature = fromHex("signature", env.signature);

  if (iv.length !== 12) {
    throw new UtaError(`iv must be 12 bytes, got ${iv.length}`);
  }
  if (ct.length < 16) {
    throw new UtaError(`ct must be at least 16 bytes (auth tag), got ${ct.length}`);
  }

  // 3. PSS verify
  const signed = Buffer.concat([ek, iv, ct]);
  let ok: boolean;
  try {
    ok = verify(
      "sha256",
      signed,
      {
        key: opts.marketPublicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO,
      },
      signature,
    );
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new UtaSignatureError("launch envelope signature verification failed");
  }

  // 4. OAEP unwrap
  let aesKey: Buffer;
  try {
    aesKey = privateDecrypt(
      {
        key: opts.developerPrivateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
        // mgf1Hash is not in @types/node for all versions; passed via cast.
      } as Parameters<typeof privateDecrypt>[0],
      ek,
    );
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaError(`failed to unwrap AES key: ${err}`);
  }
  if (aesKey.length !== 32) {
    throw new UtaError(`unwrapped AES key has wrong length: ${aesKey.length}`);
  }

  // 5. AES-256-GCM decrypt. Python's AESGCM emits `ciphertext || tag`; Node
  // takes them separately, so split the trailing 16-byte tag off `ct`.
  const tag = ct.subarray(ct.length - 16);
  const body = ct.subarray(0, ct.length - 16);
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAAD(Buffer.concat([ek, iv]));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new UtaError("AES-GCM authentication failed (ciphertext tampered)");
  }

  // 6. JSON parse
  let inner: unknown;
  try {
    inner = JSON.parse(plaintext.toString("utf8"));
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new UtaError(`decrypted plaintext is not valid JSON: ${err}`);
  }
  if (inner === null || typeof inner !== "object" || Array.isArray(inner)) {
    throw new UtaError("decrypted plaintext is not a JSON object");
  }
  return inner as InnerPayload;
}

export interface BuildPayloadOptions {
  user_key: string;
  app_id: string;
  developer_public_key: KeyObject;
  market_private_key: KeyObject;
  iat?: number;
  exp_seconds?: number;
  nonce?: string;
  version_hint?: string;
  kind?: string;
}

/**
 * Build a launch envelope. Intended for tests and for the marketplace-side
 * implementation. The SDK itself only *unpacks* envelopes in production.
 */
export function buildPayload(opts: BuildPayloadOptions): string {
  const now = opts.iat ?? Math.floor(Date.now() / 1000);
  const expSeconds = opts.exp_seconds ?? 300;
  const kind = opts.kind ?? "launch";
  const nonce = opts.nonce ?? randomBytes(16).toString("hex");

  const inner: Record<string, unknown> = {
    kind,
    user_key: opts.user_key,
    app_id: opts.app_id,
    iat: now,
    exp: now + expSeconds,
    nonce,
  };
  if (opts.version_hint !== undefined) {
    inner.version_hint = opts.version_hint;
  }

  const plaintext = Buffer.from(JSON.stringify(inner), "utf8");

  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  const ek = publicEncrypt(
    {
      key: opts.developer_public_key,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    } as Parameters<typeof publicEncrypt>[0],
    aesKey,
  );

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(Buffer.concat([ek, iv]));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ct = Buffer.concat([body, tag]);

  const signature = sign("sha256", Buffer.concat([ek, iv, ct]), {
    key: opts.market_private_key,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
  });

  const envelope: Envelope = {
    v: ENVELOPE_VERSION,
    alg: ALG_LABEL,
    ek: ek.toString("hex"),
    iv: iv.toString("hex"),
    ct: ct.toString("hex"),
    signature: signature.toString("hex"),
  };
  return JSON.stringify(envelope);
}
