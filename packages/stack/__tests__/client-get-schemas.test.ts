import { describe, expect, it } from 'vitest'
import { createEncryptionClient } from '@/encryption/client-v3'
import { encryptedTable, types } from '@/eql/v3'

/**
 * `getSchemas()` exists so that a tool holding only the client can recover the
 * DECLARED domain of every column. `getEncryptConfig()` cannot answer that:
 * `EncryptedV3Column.build()` emits `{ cast_as, indexes }` and drops the domain
 * name, so `cast_as: 'number'` + `{ ope: {} }` is ambiguous across five numeric
 * ordering domains. `stash eql validate` reads the domain to steer `_ord_ore`
 * columns and to drift-check against `information_schema.columns.domain_name`.
 *
 * The stub below is the same shape `typed-client-v3.test.ts` uses — the wrapper
 * takes the NATIVE client, and `getSchemas` is pure pass-through, so no FFI,
 * credentials or network are involved.
 */
type NativeClientStub = Parameters<typeof createEncryptionClient>[0]

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  age: types.IntegerOrd('age'),
  createdOn: types.Date('created_on'),
})

const orders = encryptedTable('orders', {
  total: types.NumericOrdOre('total'),
})

const nativeStub = {} as unknown as NativeClientStub

describe('EncryptionClient.getSchemas', () => {
  it('returns the registered tables, in order, by reference', () => {
    const client = createEncryptionClient(nativeStub, users, orders)

    expect(client.getSchemas()).toEqual([users, orders])
    // By reference, not a copy: consumers pass these straight back into
    // `encryptModel(model, table)` / `decryptModel(row, table)`.
    expect(client.getSchemas()[0]).toBe(users)
    expect(client.getSchemas()[1]).toBe(orders)
  })

  it('round-trips each column to its concrete EQL v3 domain', () => {
    const client = createEncryptionClient(nativeStub, users, orders)

    const domains = client.getSchemas().flatMap((table) =>
      Object.values(table.columnBuilders).map((column) => ({
        table: table.tableName,
        column: column.getName(),
        eqlType: column.getEqlType(),
        queryable: column.isQueryable(),
      })),
    )

    expect(domains).toEqual([
      {
        table: 'users',
        column: 'email',
        eqlType: 'public.eql_v3_text_search',
        queryable: true,
      },
      {
        table: 'users',
        column: 'age',
        eqlType: 'public.eql_v3_integer_ord',
        queryable: true,
      },
      {
        table: 'users',
        // The DB name (`getName()`), not the JS property `createdOn` — the
        // whole point of reading through the builder rather than the key.
        column: 'created_on',
        eqlType: 'public.eql_v3_date',
        queryable: false,
      },
      {
        table: 'orders',
        column: 'total',
        eqlType: 'public.eql_v3_numeric_ord_ore',
        queryable: true,
      },
    ])
  })

  it('recovers a domain the encrypt config cannot distinguish', () => {
    // `IntegerOrd` and `DoubleOrd` build to the SAME encrypt-config column —
    // this is the ambiguity `getSchemas()` exists to resolve.
    const ambiguous = encryptedTable('t', {
      a: types.IntegerOrd('a'),
      b: types.DoubleOrd('b'),
    })
    const client = createEncryptionClient(nativeStub, ambiguous)

    const built = ambiguous.build().columns
    expect(built.a).toEqual(built.b)

    const [first, second] = Object.values(
      client.getSchemas()[0].columnBuilders,
    ).map((column) => column.getEqlType())
    expect(first).toBe('public.eql_v3_integer_ord')
    expect(second).toBe('public.eql_v3_double_ord')
  })
})

describe('the tuple getSchemas() hands back', () => {
  /**
   * The client derives its per-table reconstructor map ONCE, at construction,
   * from this tuple. A consumer that mutated the array afterwards would leave
   * `getSchemas()` describing a schema set the client does not actually
   * reconstruct for. The readonly tuple type blocks that from TypeScript;
   * freezing closes it for untyped callers too, at no runtime cost.
   */
  it('is frozen, so it cannot drift from the client it describes', () => {
    const users = encryptedTable('users', { email: types.TextEq('email') })
    const client = createEncryptionClient(nativeStub, users)

    expect(Object.isFrozen(client.getSchemas())).toBe(true)
  })

  it('is the same tuple on every call', () => {
    const users = encryptedTable('users', { email: types.TextEq('email') })
    const client = createEncryptionClient(nativeStub, users)

    expect(client.getSchemas()).toBe(client.getSchemas())
  })
})
