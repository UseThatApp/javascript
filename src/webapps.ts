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
  contents?: string;
  content?: string;
};

/**
 * Verify a hex signature and decrypt a hex-encoded encrypted message from a JSON message.
 */
export function getVersion(
  message: string | ProductMessage,
  publicKeyPath: string,
  privateKeyPath: string,
  encoding: BufferEncoding = "utf8",
): string | Buffer {
  let messageObj: ProductMessage;
  if (typeof message === "string") {
    try {
      messageObj = JSON.parse(message) as ProductMessage;
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      throw new Error(`failed to parse message JSON: ${err}`);
    }
  } else if (message !== null && typeof message === "object") {
    messageObj = message;
  } else {
    throw new Error("message must be an object or JSON string");
  }

  if (!Object.prototype.hasOwnProperty.call(messageObj, "signature")) {
    throw new Error("message must contain 'signature' and 'contents' fields");
  }
  const signatureHex = messageObj.signature;
  const encryptedMessageHex = messageObj.contents ?? messageObj.content;

  if (encryptedMessageHex == null) {
    throw new Error("message missing 'contents' field");
  }

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

  const verified = verifySignature(publicKey, signature, encryptedMessage);
  if (!verified) {
    throw new Error("signature verification failed");
  }

  const decrypted = decryptMessage(privateKey, encryptedMessage);

  try {
    return decrypted.toString(encoding);
  } catch {
    return decrypted;
  }
}
