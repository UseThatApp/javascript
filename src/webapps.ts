import { Keys, decryptMessage, verifySignature } from "./encryption.js";
import type { KeyObject } from "node:crypto";

function normalizeHex(h: string): string {
  if (h == null) {
    throw new Error("hex input is null or undefined");
  }
  let s = h.trim();
  if (s.startsWith("0x") || s.startsWith("0X")) {
    s = s.slice(2);
  }
  if (s.length % 2 !== 0) {
    throw new Error("invalid hex string (odd length)");
  }
  return s;
}

export type ProductMessage = {
  signature: string;
  contents: string;
};

export type Envelope = {
  type: string;
  responseTo?: string;
  message?: ProductMessage | string;
};

/**
 * Verify and decrypt an access-level response from `requestAccessLevel()`.
 *
 * The *envelope* is the object resolved by the `requestAccessLevel()`
 * JavaScript function exposed by **usethatapp.js**.  It has the shape:
 *
 * ```json
 * {
 *   "type": "level",
 *   "responseTo": "<request-id>",
 *   "message": {
 *     "contents": "<hex-encrypted-license>",
 *     "signature": "<hex-signature>"
 *   }
 * }
 * ```
 *
 * If the envelope carries an error (`type` === `"error"`), an `Error` is
 * thrown with the server's error description.
 *
 * @param envelope — a plain object or JSON string — the full postMessage
 *                   envelope returned by `requestAccessLevel()`.
 * @param publicKeyPath — path to the UseThatApp PEM public key file used
 *                        to verify the signature.
 * @param privateKeyPath — path to the developer's PEM private key file
 *                         used to decrypt the message.
 * @param encoding — the decrypted bytes will be decoded to a string using
 *                   this encoding; if decoding fails the raw Buffer is
 *                   returned.
 * @returns The decrypted product name as a string (when decoding succeeds)
 *          or a Buffer.
 * @throws {Error} on invalid envelope, error responses, missing keys,
 *                 or failed signature verification.
 */
export function getVersion(
  envelope: string | Envelope,
  publicKeyPath: string,
  privateKeyPath: string,
  encoding: BufferEncoding = "utf8",
): string | Buffer {
  // ── parse input ──────────────────────────────────────────────────
  let envelopeObj: Envelope;
  if (typeof envelope === "string") {
    try {
      envelopeObj = JSON.parse(envelope) as Envelope;
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      throw new Error(`failed to parse envelope JSON: ${err}`);
    }
  } else if (envelope !== null && typeof envelope === "object") {
    envelopeObj = envelope;
  } else {
    throw new Error("envelope must be an object or JSON string");
  }

  // ── check envelope type ──────────────────────────────────────────
  const msgType = envelopeObj.type;
  if (msgType === "error") {
    const errorDetail = envelopeObj.message ?? "Unknown error";
    throw new Error(`server error: ${errorDetail}`);
  }
  if (msgType !== "level") {
    throw new Error(
      `unexpected envelope type '${msgType}': expected 'level'`,
    );
  }

  // ── extract payload from envelope.message ────────────────────────
  const payload = envelopeObj.message;
  if (payload == null || typeof payload !== "object") {
    throw new Error("envelope 'message' field must be an object");
  }

  const signatureHex = payload.signature;
  const encryptedMessageHex = payload.contents;

  if (signatureHex == null) {
    throw new Error("payload missing 'signature' field");
  }
  if (encryptedMessageHex == null) {
    throw new Error("payload missing 'contents' field");
  }

  // ── hex → Buffers ────────────────────────────────────────────────
  let signature: Buffer;
  let encryptedMessage: Buffer;
  try {
    const sigHex = normalizeHex(signatureHex);
    const msgHex = normalizeHex(encryptedMessageHex);
    signature = Buffer.from(sigHex, "hex");
    encryptedMessage = Buffer.from(msgHex, "hex");
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new Error(`invalid hex input: ${err}`);
  }

  // ── load keys ────────────────────────────────────────────────────
  let publicKey: KeyObject;
  let privateKey: KeyObject;
  try {
    publicKey = Keys.readPublicKeyFromFile(publicKeyPath);
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new Error(`failed to read public key from '${publicKeyPath}': ${err}`);
  }

  try {
    privateKey = Keys.readPrivateKeyFromFile(privateKeyPath);
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    throw new Error(`failed to read private key from '${privateKeyPath}': ${err}`);
  }

  // ── verify signature ─────────────────────────────────────────────
  if (!verifySignature(publicKey, signature, encryptedMessage)) {
    throw new Error("signature verification failed");
  }

  // ── decrypt ──────────────────────────────────────────────────────
  const decrypted = decryptMessage(privateKey, encryptedMessage);

  try {
    return decrypted.toString(encoding);
  } catch {
    return decrypted;
  }
}
