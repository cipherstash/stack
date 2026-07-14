/**
 * WASM smoke test for `@cipherstash/stack/wasm-inline`.
 *
 * Runs under Deno against real CipherStash credentials. Proves four things
 * together:
 *   1. The stack `/wasm-inline` subpath resolves under Deno (no native
 *      binding required).
 *   2. The entry is EQL v3: a schema authored with the `types` DSL round-trips.
 *      `TextSearch` maps to the concrete `eql_v3_text_search` domain, which a
 *      v2-mode client cannot resolve — so a successful round-trip proves the
 *      factory pinned `eqlVersion: 3` (#614).
 *   3. The WASM protect-ffi client completes an encrypt → decrypt round-trip
 *      against ZeroKMS / CTS.
 *   4. No FFI permission was granted to the Deno process, so the WASM path is
 *      the *only* path that could have succeeded.
 *
 * Skipped when any of the four CS_* env vars is missing — matches the skip
 * pattern in `e2e/tests/*.e2e.test.ts`.
 */

import { assertEquals, assertExists } from 'jsr:@std/assert@^1.0.0'
import {
  Encryption,
  encryptedTable,
  isEncrypted,
  types,
} from '@cipherstash/stack/wasm-inline'

// `CS_WORKSPACE_CRN` is the single source of truth for workspace
// identity and region — the stack `/wasm-inline` config requires it and
// derives the `AccessKeyStrategy` region from it. `CS_REGION` is not
// consulted.
const REQUIRED_ENV = [
  'CS_WORKSPACE_CRN',
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
  name: 'stack/wasm-inline: EQL v3 encrypt → decrypt round-trip via WASM',
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
    assertExists(
      globalThis.Deno,
      'Deno global missing (test framework misconfigured)',
    )

    // A v3 table authored with the `types` DSL re-exported from `/wasm-inline`.
    // `TextSearch` maps to `eql_v3_text_search`, which only a v3-mode client
    // can resolve — so this round-trip proves the factory selected eqlVersion 3.
    const users = encryptedTable('protect-ci', {
      email: types.TextSearch('email'),
    })

    const client = await Encryption({
      schemas: [users],
      config: {
        // CRN is the single source of truth — the region the
        // AccessKeyStrategy needs is derived from it.
        workspaceCrn: env!.CS_WORKSPACE_CRN,
        accessKey: env!.CS_CLIENT_ACCESS_KEY,
        clientId: env!.CS_CLIENT_ID,
        clientKey: env!.CS_CLIENT_KEY,
      },
    })

    const plaintext = `wasm-v3-smoke-${crypto.randomUUID()}@example.com`

    const encrypted = await client.encrypt(plaintext, {
      column: users.email,
      table: users,
    })

    assertEquals(
      isEncrypted(encrypted),
      true,
      'encrypt() did not return a recognised EQL payload',
    )

    const decrypted = await client.decrypt(encrypted)
    assertEquals(decrypted, plaintext, 'round-trip plaintext mismatch')
  },
})
