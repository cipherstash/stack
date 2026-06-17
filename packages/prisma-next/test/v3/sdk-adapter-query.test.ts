/**
 * Behaviour pins for `createCipherstashSdk(...).bulkEncryptQuery` — the v3
 * search-term path that maps to the stack client's `encryptQuery`.
 */
import type { EncryptionClient } from '@cipherstash/stack/client'
import { encryptedColumn, encryptedTable } from '@cipherstash/stack/schema'
import { describe, expect, it, vi } from 'vitest'
import { createCipherstashSdk } from '../../src/stack/sdk-adapter'

describe('CipherstashSdk.bulkEncryptQuery', () => {
  it('delegates to encryptQuery with column/table + queryType=eql returnType, returning the term array directly', async () => {
    const searchTerm = { v: 2, i: { t: 'users', c: 'email' }, hm: 'h' }
    const encryptQuery = vi.fn(async (terms: ReadonlyArray<unknown>) => ({
      failure: null,
      // encryptQuery returns the search terms DIRECTLY (no `{ data }` wrapper per term).
      data: terms.map(() => searchTerm),
    }))
    const client = { encryptQuery } as unknown as EncryptionClient

    const users = encryptedTable('users', { email: encryptedColumn('email').equality() })
    const sdk = createCipherstashSdk(client, [users])

    const terms = await sdk.bulkEncryptQuery!({
      routingKey: { table: 'users', column: 'email' },
      queryType: 'equality',
      values: ['alice'],
    })

    expect(encryptQuery).toHaveBeenCalledOnce()
    const passed = encryptQuery.mock.calls[0]![0] as ReadonlyArray<Record<string, unknown>>
    expect(passed).toHaveLength(1)
    expect(passed[0]).toMatchObject({ value: 'alice', queryType: 'equality', returnType: 'eql' })
    // column/table are the resolved typed schema objects, not the routing-key strings.
    expect((passed[0]!.column as { columnName?: string }).columnName).toBe('email')
    expect(passed[0]!.table).toBe(users)
    // returned array is the bare term list — NO `.data` unwrap layer.
    expect(terms).toEqual([searchTerm])
  })

  it("uses the queryType verbatim against the protect query-type union ('equality'|'orderAndRange'|'freeTextSearch')", async () => {
    const encryptQuery = vi.fn(async (terms: ReadonlyArray<unknown>) => ({ failure: null, data: terms.map(() => ({})) }))
    const client = { encryptQuery } as unknown as EncryptionClient
    const users = encryptedTable('users', { name: encryptedColumn('name').orderAndRange() })
    const sdk = createCipherstashSdk(client, [users])
    await sdk.bulkEncryptQuery!({ routingKey: { table: 'users', column: 'name' }, queryType: 'orderAndRange', values: ['m'] })
    const passed = encryptQuery.mock.calls[0]![0] as ReadonlyArray<Record<string, unknown>>
    expect(passed[0]!.queryType).toBe('orderAndRange')
  })

  it('surfaces an encryptQuery failure as a thrown Error carrying the op name + message', async () => {
    // The `failure: null` happy path is covered above; this pins the failure
    // branch of `unwrap(result, 'bulkEncryptQuery')`.
    const encryptQuery = vi.fn(async () => ({ failure: { message: 'kms unavailable' } }))
    const client = { encryptQuery } as unknown as EncryptionClient
    const users = encryptedTable('users', { email: encryptedColumn('email').equality() })
    const sdk = createCipherstashSdk(client, [users])

    await expect(
      sdk.bulkEncryptQuery!({ routingKey: { table: 'users', column: 'email' }, queryType: 'equality', values: ['alice'] }),
    ).rejects.toThrow(/cipherstash bulkEncryptQuery failed: kms unavailable/)
    expect(encryptQuery).toHaveBeenCalledOnce()
  })
})
