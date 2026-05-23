# fastify-min

Fastify launch endpoint.

## Run

```bash
npm install fastify @fastify/formbody
export UTA_APP_ID=...
export UTA_PRIVATE_KEY="$(cat my_private.pem)"
node examples/fastify-min/app.mjs
```

Why `@fastify/formbody`: Fastify only parses `application/json` out of
the box, but the marketplace POSTs `application/x-www-form-urlencoded`.
This plugin adds the missing parser.
