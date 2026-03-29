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

Load the UseThatApp script on the client, then pass the message from your frontend into the server and call `getProduct` with your PEM key paths.

### Example (Express)

```javascript
import express from "express";
import { getProduct } from "usethatapp/webapps";

const app = express();
app.use(express.json());

app.post("/license", (req, res) => {
  try {
    const message = req.body?.message ?? req.body;
    const product = getProduct(
      message,
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
import { getProduct } from "usethatapp/webapps";

const message = process.env.UTA_MESSAGE_JSON; // or object from your web layer
const product = getProduct(
  message,
  "/path/to/UseThatApp_public.pem",
  "/path/to/my_UTA_private.pem",
);
console.log(product);
```

### Message shape

`getProduct` accepts either a **JSON string** or an object with:

| Field | Description |
|--------|-------------|
| `signature` | Hex string (optional `0x` prefix) |
| `contents` | Hex-encoded ciphertext (preferred) |
| `content` | Same as `contents` if you need the alternate key |

On success you get a UTF-8 `string` when decoding succeeds, otherwise a `Buffer`.

## API

### `getProduct(message, publicKeyPath, privateKeyPath, encoding?)`

- **message** — `string` (JSON) or `ProductMessage` object  
- **publicKeyPath** — filesystem path to the UseThatApp **public** PEM (signature verification)  
- **privateKeyPath** — filesystem path to **your** private PEM (decryption)  
- **encoding** — optional `BufferEncoding` for the decrypted payload (default `"utf8"`)

Throws `Error` for invalid JSON, bad hex, verification failure, missing fields, or key read errors.

### Lower-level exports

Useful if you already load keys yourself:

- **`Keys.readPublicKeyFromFile` / `readPrivateKeyFromFile`** — PEM from disk  
- **`Keys.readPublicKeyFromString` / `readPrivateKeyFromString`** — PEM string (supports C-style `\\n` / `\\xNN` escapes in the string)  
- **`verifySignature(publicKey, signature, message)`** — `Buffer` inputs  
- **`decryptMessage(privateKey, encrypted)`** — returns `Buffer`  

Types are published in `dist/*.d.ts`; import `type { ProductMessage }` when you need the message type.

## Client script

Include the UseThatApp browser script so the access payload is available to your app:

`https://cdn.jsdelivr.net/gh/UseThatApp/cdn@latest/usethatapp.js`

Your server should receive the same `message` payload that the browser script provides to your app.

## Development

```bash
npm install
npm run build
```

- **`npm run test:compat`** — builds a signed+encrypted payload with Node’s `crypto` and checks that `getProduct` verifies and decrypts it.

## Changelog

### 0.1.0

- Initial release

## License

MIT
