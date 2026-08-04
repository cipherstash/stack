// Unknown keys in an options object are rejected, not silently dropped (#144).
//
// Every test here casts past the TypeScript types on purpose. Those types are
// the first line of defence and catch these mistakes at compile time (#142) —
// but only for TypeScript callers. Plain JS, Deno without type-checking, and
// anything arriving through a `JSON.parse` boundary reach serde unchecked, and
// this is what happens to them there.
//
// The wasm half lives in `wasm-round-trip.test.ts` (`wasm newClient
// validation`), where the wasm loader already is. It matters more there: on
// that boundary serde only sees keys a struct declares, so rejecting anything
// at all takes the `DenyUnknown` marker in `crates/protect-ffi/src/lib.rs`.

import 'dotenv/config'
import { beforeAll, describe, expect, test } from 'vitest'

import {
  type Client,
  type EncryptConfig,
  type NewClientOptions,
  encrypt,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'

const encryptConfig: EncryptConfig = {
  v: 1,
  tables: { users: { email: { cast_as: 'text', indexes: { unique: {} } } } },
}

/** Options a JS caller could construct but the TS types would reject. */
function untyped(opts: Record<string, unknown>): NewClientOptions {
  return opts as NewClientOptions
}

describe('newClient rejects unknown option keys', () => {
  test('credentials at the top level instead of under clientOpts', async () => {
    // The incident behind #144. Dropped silently, these surfaced later as
    // "clientId and clientKey are required" — with the caller looking straight
    // at them in the call they had just written.
    await expect(
      newClient(
        untyped({
          encryptConfig,
          clientId: '8f7ae6de-6b6a-4f9e-9dd4-2b2e39bc3b52',
          clientKey: 'ab',
        }),
      ),
    ).rejects.toThrow(/unknown field `clientId`/)
  })

  test('an unknown key inside clientOpts', async () => {
    await expect(
      newClient(
        untyped({ encryptConfig, clientOpts: { region: 'ap-southeast-2' } }),
      ),
    ).rejects.toThrow(/unknown field `region`/)
  })

  test('an unknown key at the top level', async () => {
    // This one is about the JS wrapper, not serde: `newClient` used to rebuild
    // the native options object field by field, which dropped anything it
    // didn't name before the Rust could complain. It now forwards the rest
    // verbatim.
    await expect(
      newClient(untyped({ encryptConfig, eqlVerison: 3 })),
    ).rejects.toThrow(/unknown field `eqlVerison`/)
  })

  test('the documented shape still constructs a client', async () => {
    await expect(
      newClient({ encryptConfig, eqlVersion: 2 }),
    ).resolves.toBeDefined()
  })
})

describe('encrypt rejects unknown option keys', () => {
  let client: Client

  beforeAll(async () => {
    client = await newClient({ encryptConfig })
  })

  test('a misspelled unverifiedContext', async () => {
    await expect(
      encrypt(client, {
        plaintext: 'alice@example.com',
        table: 'users',
        column: 'email',
        unverifedContext: { sub: 'user-1' },
      } as unknown as Parameters<typeof encrypt>[1]),
    ).rejects.toThrow(/unknown field `unverifedContext`/)
  })

  test('a lockContext on the bulk options instead of on each payload', async () => {
    // The security case. `lockContext` is per-payload on a bulk call; at the
    // top level it was dropped and every value encrypted UNBOUND while the
    // caller believed it was identity-bound. Nothing in the output
    // distinguishes the two, so this had to fail loudly or not at all.
    await expect(
      encryptBulk(client, {
        plaintexts: [
          { plaintext: 'alice@example.com', table: 'users', column: 'email' },
        ],
        lockContext: { identityClaim: ['sub'] },
      } as unknown as Parameters<typeof encryptBulk>[1]),
    ).rejects.toThrow(/unknown field `lockContext`/)
  })
})
