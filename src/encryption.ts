import {
  createPrivateKey,
  createPublicKey,
  constants,
  privateDecrypt,
  verify,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * Decode a PEM string that uses C-style escapes (e.g. literal `\n` for newline, `\xNN`, `\uNNNN`).
 */
function pemFromUnicodeEscaped(pemStr: string): string {
  const b = Buffer.from(pemStr, "utf8");
  const parts: string[] = [];
  let i = 0;
  while (i < b.length) {
    if (b[i] === 0x5c) {
      i++;
      if (i >= b.length) {
        parts.push("\\");
        break;
      }
      const c = b[i];
      if (c === 0x6e) {
        parts.push("\n");
        i++;
        continue;
      }
      if (c === 0x72) {
        parts.push("\r");
        i++;
        continue;
      }
      if (c === 0x74) {
        parts.push("\t");
        i++;
        continue;
      }
      if (c === 0x5c) {
        parts.push("\\");
        i++;
        continue;
      }
      if (c === 0x78 && i + 2 < b.length) {
        const hex = b.subarray(i + 1, i + 3).toString("ascii");
        parts.push(String.fromCharCode(parseInt(hex, 16)));
        i += 3;
        continue;
      }
      if (c === 0x75 && i + 4 < b.length) {
        const hex = b.subarray(i + 1, i + 5).toString("ascii");
        parts.push(String.fromCharCode(parseInt(hex, 16)));
        i += 5;
        continue;
      }
      parts.push(String.fromCharCode(c));
      i++;
      continue;
    }
    parts.push(String.fromCharCode(b[i]!));
    i++;
  }
  return parts.join("");
}

export function decryptMessage(privateKey: KeyObject, encryptedMessage: Buffer): Buffer {
  // mgf1Hash: OAEP MGF1(SHA256); typings omit mgf1Hash on some @types/node versions.
  const opts = {
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256" as const,
    mgf1Hash: "sha256" as const,
  };
  return privateDecrypt(opts as Parameters<typeof privateDecrypt>[0], encryptedMessage);
}

export function verifySignature(
  publicKey: KeyObject,
  signature: Buffer,
  message: Buffer,
): boolean {
  try {
    return verify(
      "sha256",
      message,
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
      },
      signature,
    );
  } catch {
    return false;
  }
}

export class Keys {
  static readPublicKeyFromString(pemStr: string): KeyObject {
    const pem = pemFromUnicodeEscaped(pemStr);
    return createPublicKey(pem);
  }

  static readPublicKeyFromFile(filePath: string): KeyObject {
    return createPublicKey(readFileSync(filePath));
  }

  static readPrivateKeyFromString(pemStr: string): KeyObject {
    const pem = pemFromUnicodeEscaped(pemStr);
    return createPrivateKey(pem);
  }

  static readPrivateKeyFromFile(filePath: string): KeyObject {
    return createPrivateKey(readFileSync(filePath));
  }
}
