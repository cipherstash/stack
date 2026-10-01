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

import type { AuthFailure } from '../index'
import { beginDeviceCodeFlow } from '../index'

function reportAndExit(failure: AuthFailure): never {
  console.error(`[${failure.type}] ${failure.error.message}`)
  process.exit(1)
}

async function main() {
  // Step 1: Begin the device code flow
  const begun = await beginDeviceCodeFlow('ap-southeast-2.aws', 'cli')
  if (begun.failure) reportAndExit(begun.failure)
  const pending = begun.data

  // Step 2: Show the user their code and verification URL
  console.log(`Your code is: ${pending.userCode}`)
  console.log(`Visit: ${pending.verificationUriComplete}`)
  console.log(`Code expires in: ${pending.expiresIn}s`)
  console.log()

  // Optionally open the browser automatically
  const opened = pending.openInBrowser()
  if (opened.failure) reportAndExit(opened.failure)
  if (!opened.data) {
    console.log('Could not open browser — please visit the URL above manually.')
  }

  // Step 3: Poll until the user authorizes (or the code expires).
  //         The token is saved to ~/.cipherstash/auth.json automatically.
  console.log('Waiting for authorization...')
  const result = await pending.pollForToken()
  if (result.failure) reportAndExit(result.failure)
  const auth = result.data

  console.log()
  console.log('Authenticated! Token saved to ~/.cipherstash/auth.json')
  console.log(`  Expires at: ${new Date(auth.expiresAt * 1000).toISOString()}`)
  console.log(`  Expires in: ${auth.expiresIn}s`)
}

// Domain errors are returned as `failure`, not thrown — only a genuine
// internal fault reaches here.
main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
