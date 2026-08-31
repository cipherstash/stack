/**
 * Per-item failures in `bulkDecrypt`, on the native entry.
 *
 * `decryptBulkFallible` reports success or failure PER ITEM — one undecryptable
 * row does not fail the call — and since this branch a failed item carries the
 * same diagnostic the whole-call failure does: `code`, plus `authCode` and
 * `help` when CTS refused the token behind the request. `bulkDecrypt` returns
 * `{ data }` in that case (the call succeeded; some rows did not), so the row
 * IS the only surface those fields have. Copying only `error` across made the
 * new per-item fields unreachable from `@cipherstash/stack`.
 *
 * Credential-free: protect-ffi is mocked, so there is no ZeroKMS round-trip.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const CTS_MESSAGE = 'Insufficient balance. Please upgrade your plan.'
const CTS_HELP = 'Upgrade the plan from the CipherStash dashboard, then retry.'

vi.mock('@cipherstash/protect-ffi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/protect-ffi')>()),
  newClient: vi.fn(async () => ({ __mock: 'client' })),
  decryptBulkFallible: vi.fn(async () => [{ data: 'plain' }]),
}))

import * as ffi from '@cipherstash/protect-ffi'
import { encryptedTable, types } from '@/encryption/v3'
import { Encryption } from '@/index'

const users = encryptedTable('users', { email: types.TextEq('email') })

const ct = () => ({ v: 3, i: { t: 'users', c: 'email' }, c: 'x' }) as never

beforeEach(() => {
  vi.clearAllMocks()
})

describe('a per-item decrypt failure', () => {
  it('carries the auth code and help onto the row', async () => {
    vi.mocked(ffi.decryptBulkFallible).mockResolvedValueOnce([
      { error: CTS_MESSAGE, authCode: 'USAGE_LIMIT_EXCEEDED', help: CTS_HELP },
    ])

    const client = await Encryption({ schemas: [users] })
    const result = await client.bulkDecrypt([{ id: 'row-1', data: ct() }])

    const row = result.data?.[0]
    expect(row).toMatchObject({
      id: 'row-1',
      error: CTS_MESSAGE,
      authCode: 'USAGE_LIMIT_EXCEEDED',
      help: CTS_HELP,
    })
  })

  it('keeps the protect-ffi error code it always had a field for', async () => {
    vi.mocked(ffi.decryptBulkFallible).mockResolvedValueOnce([
      { error: 'bad ciphertext', code: 'INVALID_CIPHERTEXT' },
    ])

    const client = await Encryption({ schemas: [users] })
    const result = await client.bulkDecrypt([{ data: ct() }])

    expect(result.data?.[0]).toMatchObject({
      error: 'bad ciphertext',
      code: 'INVALID_CIPHERTEXT',
    })
  })

  // The mapping must carry the FFI's diagnostic through rather than enumerate
  // it: protect-ffi is adding `url` alongside `help` on the same miette
  // surface, and a field list here would silently drop it until someone
  // remembered to come back. Pinned with a key this build does not know so the
  // test still proves the shape after `url` lands.
  it('carries a diagnostic field this build has never heard of', async () => {
    vi.mocked(ffi.decryptBulkFallible).mockResolvedValueOnce([
      {
        error: CTS_MESSAGE,
        authCode: 'USAGE_LIMIT_EXCEEDED',
        url: 'https://cipherstash.com/docs/errors/usage-limit',
        somethingLater: 'still here',
      },
    ] as never)

    const client = await Encryption({ schemas: [users] })
    const result = await client.bulkDecrypt([{ data: ct() }])

    expect(result.data?.[0]).toMatchObject({
      url: 'https://cipherstash.com/docs/errors/usage-limit',
      somethingLater: 'still here',
    })
  })

  it('leaves a successful row exactly as it was', async () => {
    vi.mocked(ffi.decryptBulkFallible).mockResolvedValueOnce([
      { data: 'person@example.com' },
    ])

    const client = await Encryption({ schemas: [users] })
    const result = await client.bulkDecrypt([{ id: 'row-1', data: ct() }])

    expect(result.data?.[0]).toEqual({
      id: 'row-1',
      data: 'person@example.com',
    })
  })

  // Null inputs keep their position and stay bare — the mapping change must not
  // leak diagnostic keys onto rows that never reached the FFI.
  it('keeps null inputs positional and undecorated', async () => {
    vi.mocked(ffi.decryptBulkFallible).mockResolvedValueOnce([
      { error: CTS_MESSAGE, authCode: 'USAGE_LIMIT_EXCEEDED', help: CTS_HELP },
    ])

    const client = await Encryption({ schemas: [users] })
    const result = await client.bulkDecrypt([
      { id: 'a', data: null },
      { id: 'b', data: ct() },
    ])

    expect(result.data?.[0]).toEqual({ id: 'a', data: null })
    expect(result.data?.[1]).toMatchObject({
      id: 'b',
      authCode: 'USAGE_LIMIT_EXCEEDED',
    })
  })
})
