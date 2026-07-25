// Defense-in-depth tests for the runtime null short-circuits restored
// across the encryption operation classes. These hit the operation
// constructors directly rather than going through `Encryption()` so they
// don't need credentials or a network — the guard short-circuits before
// any FFI call. See `fix(stack): restore runtime null guards in
// encryption operations` for context.

import { describe, expect, it } from 'vitest'
import type { CryptoBackend } from '@/encryption/backend'
import { BatchEncryptQueryOperation } from '@/encryption/operations/batch-encrypt-query'
import { BulkDecryptOperation } from '@/encryption/operations/bulk-decrypt'
import { BulkEncryptOperation } from '@/encryption/operations/bulk-encrypt'
import { DecryptOperation } from '@/encryption/operations/decrypt'
import { EncryptOperation } from '@/encryption/operations/encrypt'
import { EncryptQueryOperation } from '@/encryption/operations/encrypt-query'
import { encryptedColumn, encryptedTable } from '@/schema'

const table = encryptedTable('null-guards-test', {
  metadata: encryptedColumn('metadata').searchableJson(),
})

// Any truthy stand-in — the guard returns before the client is touched.
const stubClient = {} as any

// An injected backend whose every method throws. The guard's whole job is to
// return before reaching the FFI, so reaching it should fail the test loudly
// rather than show up as an unexpected network call. Injecting this is only
// possible because operations take their backend rather than importing it
// (#798); the module-import version of this test could assert absence, but
// not presence of a violation.
const forbiddenBackend = new Proxy({} as CryptoBackend, {
  get: (_target, name) => () => {
    throw new Error(`FFI ${String(name)}() must not be reached by a null guard`)
  },
})

describe('runtime null guards (defense in depth)', () => {
  it('encrypt(null) short-circuits without an FFI call', async () => {
    const op = new EncryptOperation(stubClient, forbiddenBackend, null, {
      column: table.metadata,
      table,
    })
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toBeNull()
  })

  it('decrypt(null) short-circuits without an FFI call', async () => {
    const op = new DecryptOperation(stubClient, forbiddenBackend, null)
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toBeNull()
  })

  it('bulkEncrypt preserves null positions in mixed arrays', async () => {
    // Single null-only input — no FFI call should happen, the all-null
    // fast path returns a {data: null} placeholder per element.
    const op = new BulkEncryptOperation(
      stubClient,
      forbiddenBackend,
      [{ id: 'a', plaintext: null }],
      { column: table.metadata, table },
    )
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toEqual([{ id: 'a', data: null }])
  })

  it('bulkDecrypt preserves null positions in mixed arrays', async () => {
    const op = new BulkDecryptOperation(stubClient, forbiddenBackend, [
      { id: 'a', data: null },
    ])
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toEqual([{ id: 'a', data: null }])
  })

  it('encryptQuery(null) short-circuits to { data: null }', async () => {
    const op = new EncryptQueryOperation(stubClient, forbiddenBackend, null, {
      column: table.metadata,
      table,
      queryType: 'steVecSelector',
      returnType: 'composite-literal',
    } as any)
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toBeNull()
  })

  it('encryptQuery(undefined) short-circuits to { data: null }', async () => {
    const op = new EncryptQueryOperation(
      stubClient,
      forbiddenBackend,
      undefined,
      {
        column: table.metadata,
        table,
        queryType: 'steVecSelector',
        returnType: 'composite-literal',
      } as any,
    )
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toBeNull()
  })

  it('batchEncryptQuery preserves null/undefined slots position-stably', async () => {
    // All-null/undefined batch — no FFI call needed.
    const op = new BatchEncryptQueryOperation(stubClient, forbiddenBackend, [
      {
        column: table.metadata,
        table,
        queryType: 'steVecSelector',
        returnType: 'composite-literal',
        value: null,
      } as any,
      {
        column: table.metadata,
        table,
        queryType: 'steVecSelector',
        returnType: 'composite-literal',
        value: undefined,
      } as any,
    ])
    const result = await op.execute()
    if (result.failure) throw new Error(result.failure.message)
    expect(result.data).toEqual([null, null])
  })
})
