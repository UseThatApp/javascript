import {
  constants,
  generateKeyPairSync,
  publicEncrypt,
  sign,
} from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getVersion } from "../dist/index.js";

const dir = mkdtempSync(join(tmpdir(), "uta-"));
const pubPath = join(dir, "pub.pem");
const privPath = join(dir, "priv.pem");

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicExponent: 0x10001,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

writeFileSync(pubPath, publicKey, "utf8");
writeFileSync(privPath, privateKey, "utf8");

const plaintext = Buffer.from("Pro");
const encrypted = publicEncrypt(
  {
    key: publicKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
    mgf1Hash: "sha256",
  },
  plaintext,
);

const signature = sign("sha256", encrypted, {
  key: privateKey,
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
});

const message = JSON.stringify({
  signature: signature.toString("hex"),
  contents: encrypted.toString("hex"),
});

const out = getVersion(message, pubPath, privPath);
if (out !== "Pro") {
  console.error("expected Pro, got", out);
  process.exit(1);
}
console.log("compat ok: getVersion verifies PSS and decrypts OAEP payload");
