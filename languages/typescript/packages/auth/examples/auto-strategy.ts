// Example: Auto-detect credentials and retrieve a service token.
//
// `AutoStrategy` picks the best available authentication method:
//
//   1. Access key — if `CS_CLIENT_ACCESS_KEY` is set (along with
//      `CS_WORKSPACE_CRN`), access key auth is used.
//   2. OAuth — if `~/.cipherstash/auth.json` exists (written by
//      `stash login`), OAuth token auth is used.
//   3. If neither is available, a `NOT_AUTHENTICATED` failure is returned.
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
import type { AuthFailure } from "../index";

function reportAndExit(failure: AuthFailure): never {
  console.error(`[${failure.type}] ${failure.error.message}`);
  if (failure.help) console.error(failure.help);
  process.exit(1);
}

async function main() {
  // Detect credentials automatically from env vars / profile store.
  // You can also pass explicit values:
  //
  //   AutoStrategy.detect({ accessKey: "CSAK...", workspaceCrn: "crn:..." })
  //
  const detected = AutoStrategy.detect();
  if (detected.failure) reportAndExit(detected.failure);

  // Retrieve a token — refresh happens automatically when needed.
  const result = await detected.data.getToken();
  if (result.failure) reportAndExit(result.failure);

  const token = result.data;
  console.log(`Subject:      ${token.subject}`);
  console.log(`Workspace:    ${token.workspaceId}`);
  console.log(`Issuer:       ${token.issuer}`);
  console.log(`Services:     ${JSON.stringify(token.services)}`);
  console.log(`Token:        ${token.token.slice(0, 20)}...`);
}

// Domain errors are returned as `failure`, not thrown — only a genuine
// internal fault reaches here.
main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
