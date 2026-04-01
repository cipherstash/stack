// Example: Auto-detect credentials and retrieve a service token.
//
// `AutoStrategy` picks the best available authentication method:
//
//   1. Access key — if `CS_CLIENT_ACCESS_KEY` is set (along with
//      `CS_WORKSPACE_CRN`), access key auth is used.
//   2. OAuth — if `~/.cipherstash/auth.json` exists (written by
//      `stash login`), OAuth token auth is used.
//   3. If neither is available, a `NOT_AUTHENTICATED` error is thrown.
//
// Prerequisites:
//   1. Build the native module:  npm run build
//
// Usage (after `stash login`):
//   npx tsx examples/auto-strategy.ts
//
// Usage (with an access key):
//   CS_CLIENT_ACCESS_KEY=<key> CS_WORKSPACE_CRN=<crn> npx tsx examples/auto-strategy.ts

import { AutoStrategy } from "../index";
import type { AuthError } from "../index";

async function main() {
  // Detect credentials automatically from env vars / profile store.
  // You can also pass explicit values:
  //
  //   AutoStrategy.detect({ accessKey: "CSAK...", workspaceCrn: "crn:..." })
  //
  const strategy = AutoStrategy.detect();

  // Retrieve a token — refresh happens automatically when needed.
  const result = await strategy.getToken();

  // Who am I?
  console.log(`Subject:      ${result.subject}`);
  console.log(`Workspace:    ${result.workspaceId}`);
  console.log(`Issuer:       ${result.issuer}`);
  console.log(`Services:     ${JSON.stringify(result.services)}`);
  console.log(`Token:        ${result.token.slice(0, 20)}...`);
}

main().catch((err: AuthError) => {
  console.error(err.code ? `[${err.code}] ${err.message}` : err.message);
  process.exit(1);
});
