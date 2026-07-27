/**
 * The typed client's `init` passthrough must not reopen the door A-8 closed.
 *
 * A-7 added `init` to the typed EQL v3 client so that a caller holding it
 * through its declared `EncryptionClient` type could not hit
 * `TypeError: init is not a function`. But `EncryptionClient.init` takes its own
 * `eqlVersion?: 2 | 3`, and forwards `undefined` straight to `newClient`, where
 * the FFI's default is EQL **v2**. `resolveEqlVersion` — which refuses exactly
 * that combination — is only ever consulted by `Encryption`, never by `init`.
 *
 * So a bare passthrough lets a v3 client be silently re-initialised into v2 wire
 * while keeping the typed v3 surface: the same contradiction A-8 rejects at
 * construction, reachable one method call later.
 *
 *     const client = await Encryption({ schemas: [users] })  // eqlVersion: 3
 *     await client.init({ encryptConfig })                   // eqlVersion: undefined -> v2
 *
 * `typed-client-nominal-parity.test.ts` cannot catch this: it stubs `init` out
 * entirely and asserts only that it was called.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

// Spread the real module rather than enumerating what the code under test
// happens to reach for — `getErrorCode` calls `isProtectErrorCode`, and the
// `ProtectError` class this used to need was removed in protect-ffi 0.31.
// `importActual` loads the binding's pure-JS helpers; nothing contacts ZeroKMS,
// because `newClient` and the operations below are still overridden.
vi.mock('@cipherstash/protect-ffi', async (importActual) => ({
  ...(await importActual<typeof import('@cipherstash/protect-ffi')>()),
  newClient: vi.fn(async () => ({ __mock: 'client' })),
}))

import * as ffi from '@cipherstash/protect-ffi'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/encryption/v3'
import { Encryption } from '@/index'
import { buildEncryptConfig } from '@/schema'

const users = encryptedTable('users', { email: types.TextSearch('email') })

// biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
const newClientCalls = () => (ffi.newClient as any).mock.calls
const lastEqlVersion = () => newClientCalls().at(-1)[0].eqlVersion

beforeEach(() => {
  vi.clearAllMocks()
})

describe('typed client init keeps the v3 wire format', () => {
  it('constructs at eqlVersion 3', async () => {
    await Encryption({ schemas: [users] })

    expect(lastEqlVersion()).toBe(3)
  })

  it('stays at eqlVersion 3 when re-initialised without one', async () => {
    const client = await Encryption({ schemas: [users] })
    expect(lastEqlVersion()).toBe(3)

    await (client as unknown as EncryptionClient).init({
      encryptConfig: buildEncryptConfig(users),
    })

    // Without pinning, this is `undefined` — the FFI's v2 default — leaving a
    // typed v3 surface over a client emitting v2 payloads into eql_v3_* columns.
    expect(newClientCalls()).toHaveLength(2)
    expect(lastEqlVersion()).toBe(3)
  })

  it('refuses an explicit eqlVersion 2 on re-init, as construction does', async () => {
    const client = await Encryption({ schemas: [users] })

    // `Encryption` throws for this combination, but `init` declares
    // `Promise<Result<…>>` — the Result shape is contract, so this refuses with
    // a failure rather than rejecting. Either way it never reaches the FFI.
    const result = await (client as unknown as EncryptionClient).init({
      encryptConfig: buildEncryptConfig(users),
      eqlVersion: 2,
    })

    expect(result.failure?.message).toMatch(/eqlVersion 2|eql_v3_\* domains/)
    expect(newClientCalls()).toHaveLength(1)
  })

  it('returns the TYPED client, not the bare nominal one', async () => {
    const client = await Encryption({ schemas: [users] })

    const result = await (client as unknown as EncryptionClient).init({
      encryptConfig: buildEncryptConfig(users),
    })

    // `EncryptionClient.init` resolves `{ data: this }` — the nominal client.
    // Reassigning from it (`client = (await client.init(c)).data`) is the
    // natural idiom, and it must not silently drop the typed surface.
    if (result.failure) throw new Error(result.failure.message)
    expect(
      typeof (result.data as { encryptQuery?: unknown }).encryptQuery,
    ).toBe('function')
    expect(result.data).toBe(client)
  })
})
