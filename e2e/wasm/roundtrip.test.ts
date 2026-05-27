/**
 * WASM smoke test for `@cipherstash/stack/wasm-inline`.
 *
 * Runs under Deno against real CipherStash credentials. Proves three
 * things together:
 *   1. The stack `/wasm-inline` subpath resolves under Deno (no native
 *      binding required).
 *   2. The WASM protect-ffi client can complete an encrypt → decrypt
 *      round-trip against ZeroKMS / CTS.
 *   3. No FFI permission was granted to the Deno process, so the WASM
 *      path is the *only* path that could have succeeded.
 *
 * Skipped when any of the four CS_* env vars is missing — matches the
 * skip pattern in `e2e/tests/*.e2e.test.ts`.
 */

import { assertEquals, assertExists } from 'jsr:@std/assert@^1.0.0'
import {
  Encryption,
  encryptedColumn,
  encryptedTable,
  isEncrypted,
} from '@cipherstash/stack/wasm-inline'

// `CS_WORKSPACE_CRN` is intentionally not in this list — the WASM
// client doesn't read it (workspace identity comes from the access-key
// token). A separate ticket tracks adding parity with the Node entry,
// at which point CRN should be added back here.
const REQUIRED_ENV = [
  'CS_CLIENT_ACCESS_KEY',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
] as const

function envOrSkip(): Record<(typeof REQUIRED_ENV)[number], string> | null {
  const out: Record<string, string> = {}
  for (const name of REQUIRED_ENV) {
    const v = Deno.env.get(name)
    if (!v) return null
    out[name] = v
  }
  return out as Record<(typeof REQUIRED_ENV)[number], string>
}

const env = envOrSkip()

Deno.test({
  name: 'stack/wasm-inline: encrypt → decrypt round-trip via WASM',
  ignore: env === null,
  permissions: {
    env: true,
    net: true,
    read: true,
    sys: true,
    // No FFI permission. If protect-ffi ever silently tries a native
    // binding under Deno, the call will reject — proving WASM took the
    // request.
    ffi: false,
  },
  async fn() {
    // Sanity: we really are in Deno, and WASM is available.
    assertExists(globalThis.WebAssembly, 'WebAssembly global missing')
    assertExists(globalThis.Deno, 'Deno global missing (test framework misconfigured)')

    const users = encryptedTable('protect-ci', {
      email: encryptedColumn('email'),
    })

    const client = await Encryption({
      schemas: [users],
      config: {
        // Default region in the stack is ap-southeast-2.aws; the WASM
        // entry needs an explicit region for AccessKeyStrategy.
        region: 'ap-southeast-2.aws',
        accessKey: env!.CS_CLIENT_ACCESS_KEY,
        clientId: env!.CS_CLIENT_ID,
        clientKey: env!.CS_CLIENT_KEY,
      },
    })

    const plaintext = `wasm-smoke-${crypto.randomUUID()}@example.com`

    const encrypted = await client.encrypt(plaintext, {
      column: users.email,
      table: users,
    })

    assertEquals(isEncrypted(encrypted), true, 'encrypt() did not return a recognised EQL payload')

    const decrypted = await client.decrypt(encrypted)
    assertEquals(decrypted, plaintext, 'round-trip plaintext mismatch')
  },
})
