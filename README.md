# usethatapp

Node.js library for [UseThatApp](https://usethatapp.com) Web Apps: verify a signed payload and decrypt the licensed product string your app receives from the browser (via the UseThatApp clientside script).

Cryptography: RSA-PSS-SHA256 signature over the ciphertext, RSA-OAEP-SHA256 decryption.

**Requirements:** Node.js 18+

## Install

```bash
npm install usethatapp
```

The published package ships compiled ESM under `dist/`. There are no runtime dependencies (uses Node’s built-in `crypto`).

## Usage

Load the UseThatApp script on the client, then pass the envelope from `requestAccessLevel()` into the server and call `getVersion` with your PEM key paths.

### Example (Express)

```javascript
import express from "express";
import { getVersion } from "usethatapp/webapps";

const app = express();
app.use(express.json());

app.post("/license", (req, res) => {
  try {
    const envelope = req.body;
    const product = getVersion(
      envelope,
      process.env.USETHATAPP_PUBLIC_KEY_PEM_PATH,
      process.env.MY_UTA_PRIVATE_KEY_PEM_PATH,
    );
    res.json({ product: String(product) });
  } catch (e) {
    res.status(400).json({ error: String(e?.message ?? e) });
  }
});
```

### Example (plain Node)

```javascript
import { getVersion } from "usethatapp/webapps";

const envelope = process.env.UTA_ENVELOPE_JSON; // or object from your web layer
const product = getVersion(
  envelope,
  "/path/to/UseThatApp_public.pem",
  "/path/to/my_UTA_private.pem",
);
console.log(product);
```

### Envelope shape

`getVersion` accepts either a **JSON string** or an `Envelope` object — the full postMessage envelope returned by `requestAccessLevel()`:

| Field | Description |
|--------|-------------|
| `type` | `"level"` for a successful response; `"error"` for an error |
| `responseTo` | The request ID (optional) |
| `message` | A `ProductMessage` object with `contents` and `signature` |

The inner `ProductMessage` has:

| Field | Description |
|--------|-------------|
| `signature` | Hex string (optional `0x` prefix) |
| `contents` | Hex-encoded ciphertext |

On success you get a UTF-8 `string` when decoding succeeds, otherwise a `Buffer`.

## API

### `getVersion(envelope, publicKeyPath, privateKeyPath, encoding?)`

- **envelope** — `string` (JSON) or `Envelope` object (the full response from `requestAccessLevel()`)  
- **publicKeyPath** — filesystem path to the UseThatApp **public** PEM (signature verification)  
- **privateKeyPath** — filesystem path to **your** private PEM (decryption)  
- **encoding** — optional `BufferEncoding` for the decrypted payload (default `"utf8"`)

Throws `Error` for invalid JSON, bad hex, verification failure, missing fields, error envelopes, or key read errors.

### Lower-level exports

Useful if you already load keys yourself:

- **`Keys.readPublicKeyFromFile` / `readPrivateKeyFromFile`** — PEM from disk  
- **`Keys.readPublicKeyFromString` / `readPrivateKeyFromString`** — PEM string (supports C-style `\\n` / `\\xNN` escapes in the string)  
- **`verifySignature(publicKey, signature, message)`** — `Buffer` inputs  
- **`decryptMessage(privateKey, encrypted)`** — returns `Buffer`  

Types are published in `dist/*.d.ts`; import `type { ProductMessage, Envelope }` when you need the message types.

## Client script

Include the UseThatApp browser script so the access payload is available to your app:

`https://cdn.jsdelivr.net/gh/UseThatApp/cdn@latest/usethatapp.js`

Your server should receive the same `message` payload that the browser script provides to your app.

## Development

```bash
npm install
npm run build
```

- **`npm run test:compat`** — builds a signed+encrypted payload with Node’s `crypto` and checks that `getVersion` verifies and decrypts it.

## Changelog

### 0.2.0

- **Breaking:** `getVersion()` now expects the full `Envelope` from `requestAccessLevel()` instead of the inner `ProductMessage`
- Added `Envelope` type export
- Error envelopes (`type: "error"`) are now detected and throw with the server's error description
- Removed support for the `content` alternate key; use `contents` only

### 0.1.1

- Initial release

## License

MIT
