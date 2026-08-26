// Generates src/version.ts from package.json so SDK_VERSION can never
// drift from the published version (review finding 8: the sync test was
// the only guard, and prepublishOnly never ran it). Runs as part of
// `npm run build`, which prepublishOnly invokes.
import { readFileSync, writeFileSync } from "node:fs";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
const content = `/**
 * The installed SDK version. Exported so integrators can log it, pin it in
 * a build check, or put it in a bug report without spelunking for
 * package.json (whose subpath the exports map also now exposes).
 *
 * GENERATED from package.json by scripts/gen-version.mjs at build time —
 * do not edit by hand.
 */
export const SDK_VERSION = "${pkg.version}";
`;
writeFileSync(new URL("../src/version.ts", import.meta.url), content);
console.log(`gen-version: SDK_VERSION = "${pkg.version}"`);
