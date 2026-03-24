// Example: OAuth 2.0 Device Code flow via the @cipherstash/auth Node bindings.
//
// The token is saved automatically to ~/.cipherstash/auth.json and is never
// exposed to JavaScript.
//
// Prerequisites:
//   1. Build the native module:  npm run build
//
// Usage:
//   npx tsx examples/device-code.ts

import { beginDeviceCodeFlow } from "../index";

async function main() {
  // Step 1: Begin the device code flow
  const pending = await beginDeviceCodeFlow("ap-southeast-2.aws", "cli");

  // Step 2: Show the user their code and verification URL
  console.log(`Your code is: ${pending.userCode}`);
  console.log(`Visit: ${pending.verificationUriComplete}`);
  console.log(`Code expires in: ${pending.expiresIn}s`);
  console.log();

  // Optionally open the browser automatically
  const opened = pending.openInBrowser();
  if (!opened) {
    console.log("Could not open browser — please visit the URL above manually.");
  }

  // Step 3: Poll until the user authorizes (or the code expires).
  //         The token is saved to ~/.cipherstash/auth.json automatically.
  console.log("Waiting for authorization...");
  const auth = await pending.pollForToken();

  console.log();
  console.log("Authenticated! Token saved to ~/.cipherstash/auth.json");
  console.log(`  Expires at: ${new Date(auth.expiresAt * 1000).toISOString()}`);
  console.log(`  Expires in: ${auth.expiresIn}s`);
}

main().catch((err: Error & { code?: string }) => {
  console.error(err.code ? `[${err.code}] ${err.message}` : err.message);
  process.exit(1);
});
