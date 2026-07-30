import type { JsPlaintext } from '@cipherstash/protect-ffi'
import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
// Everything comes from the single `@cipherstash/stack/v3` surface (re-exported
// from src/encryption/v3.ts), exercising the re-export at the same time.
import {
  encryptedTable,
  types,
  type V3DecryptedModel,
  type V3EncryptedModel,
} from '@/encryption/v3'
import type { Encrypted } from '@/types'

// A v3 table mixing every relevant capability tier:
const users = encryptedTable('users', {
  email: types.TextEq('email'), // equality only
  bio: types.TextSearch('bio'), // equality + order + free-text
  note: types.Text('note'), // storage only (not queryable)
  createdAt: types.TimestampOrd('created_at'), // equality + order
})

// A second registered table whose `weight` domain (integer_ord) is NOT present in
// `users`, so borrowing it is a genuine cross-table type error.
const other = encryptedTable('other', {
  weight: types.IntegerOrd('weight'),
})

declare const client: EncryptionClient<readonly [typeof users, typeof other]>

describe('typed v3 client — encrypt plaintext is pinned to the column domain', () => {
  it('accepts the matching plaintext type per domain', () => {
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: users,
      column: users.email,
    })
    expectTypeOf(client.encrypt).toBeCallableWith(new Date(), {
      table: users,
      column: users.createdAt,
    })
  })

  it('rejects a wrong-typed plaintext', () => {
    client.encrypt(
      // @ts-expect-error - number is not valid plaintext for a text column
      123,
      { table: users, column: users.email },
    )
  })
})

describe('typed v3 client — encryptQuery constrains queryType to capabilities', () => {
  it('accepts capability-matched query types', () => {
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: users,
      column: users.email,
      queryType: 'equality',
    })
    expectTypeOf(client.encryptQuery).toBeCallableWith(new Date(), {
      table: users,
      column: users.createdAt,
      queryType: 'orderAndRange',
    })
    // text_search supports all three
    expectTypeOf(client.encryptQuery).toBeCallableWith('needle', {
      table: users,
      column: users.bio,
      queryType: 'freeTextSearch',
    })
  })

  it('rejects a query type the column does not support', () => {
    client.encryptQuery('alice@example.com', {
      table: users,
      column: users.email, // equality only
      // @ts-expect-error - text_eq column does not support 'orderAndRange'
      queryType: 'orderAndRange',
    })
    client.encryptQuery(new Date(), {
      table: users,
      column: users.createdAt, // equality + order, no free-text
      // @ts-expect-error - timestamp_ord column does not support 'freeTextSearch'
      queryType: 'freeTextSearch',
    })
  })

  it('rejects a storage-only column on the query path', () => {
    client.encryptQuery('x', {
      table: users,
      // @ts-expect-error - storage-only text column is not queryable
      column: users.note,
    })
  })

  it('keeps batch values correlated with their table and column', () => {
    client.encryptQuery([
      { value: 'alice@example.com', table: users, column: users.email },
      {
        value: new Date(),
        table: users,
        column: users.createdAt,
        queryType: 'orderAndRange',
      },
    ])

    client.encryptQuery([
      // @ts-expect-error - a timestamp column requires a Date
      {
        value: 'not-a-date',
        table: users,
        column: users.createdAt,
      },
    ])
  })
})

describe('typed v3 client — bulk encrypt derives the column plaintext', () => {
  it('accepts matching values and preserves nullable entries', () => {
    client.bulkEncrypt(
      [{ id: '1', plaintext: new Date() }, { plaintext: null }],
      { table: users, column: users.createdAt },
    )
  })

  it('rejects a value from the wrong domain', () => {
    client.bulkEncrypt(
      [
        {
          // @ts-expect-error - timestamp bulk values must be Date or null
          plaintext: 'not-a-date',
        },
      ],
      { table: users, column: users.createdAt },
    )
  })
})

describe('typed v3 client — model encrypt validates schema fields', () => {
  it('accepts a model whose schema fields match and allows passthrough fields', () => {
    expectTypeOf(client.encryptModel).toBeCallableWith(
      { id: 'u1', email: 'a@b.com', createdAt: new Date() },
      users,
    )
  })

  it('rejects a wrong-typed schema field', () => {
    client.encryptModel(
      {
        id: 'u1',
        // @ts-expect-error - email expects string, got number
        email: 123,
      },
      users,
    )
  })

  it('maps schema columns to Encrypted and preserves passthrough + nullability', () => {
    // Passthrough `id` stays string; schema `email` becomes Encrypted.
    expectTypeOf<
      V3EncryptedModel<typeof users, { id: string; email: string }>
    >().toEqualTypeOf<{ id: string; email: Encrypted }>()

    // Nullable schema field → Encrypted | null.
    expectTypeOf<
      V3EncryptedModel<typeof users, { id: string; email: string | null }>
    >().toEqualTypeOf<{ id: string; email: Encrypted | null }>()
  })
})

describe('typed v3 client — model decrypt yields precise plaintext', () => {
  it('reconstructs schema columns to their plaintext type regardless of the input field type', () => {
    // Input is the encrypted row; output pins each schema column to its plaintext
    // type (Date for timestamp, string for text).
    expectTypeOf<
      V3DecryptedModel<
        typeof users,
        { id: string; email: Encrypted; createdAt: Encrypted }
      >
    >().toEqualTypeOf<{
      id: string
      email: string
      createdAt: Date
    }>()
  })

  it('decryptModel is callable with an encrypted row and the table', () => {
    expectTypeOf(client.decryptModel).toBeCallableWith(
      { id: 'u1', email: {} as Encrypted },
      users,
    )
  })

  it('decryptModel / bulkDecryptModels are chainable with .audit() and .withLockContext()', () => {
    // The typed client's decrypt methods return a chainable operation (not a bare
    // Promise), so audit metadata and lock context can be attached before await.
    const op = client.decryptModel({ id: 'u1', email: {} as Encrypted }, users)
    expectTypeOf(op).toHaveProperty('audit')
    expectTypeOf(op).toHaveProperty('withLockContext')
    // Both stay chainable — same operation type back.
    expectTypeOf(op.audit({ metadata: { sub: 'u1' } })).toEqualTypeOf<
      typeof op
    >()

    const bulkOp = client.bulkDecryptModels(
      [{ id: 'u1', email: {} as Encrypted }],
      users,
    )
    expectTypeOf(bulkOp).toHaveProperty('audit')
    expectTypeOf(bulkOp).toHaveProperty('withLockContext')
  })
})

/**
 * The raw-vs-model `Date` boundary (#779), pinned at the layer it is argued
 * from. `typed-client-v3.test.ts` pins the runtime — that the wrapper hands the
 * stored string back untouched — but the reason it is allowed to is a type-level
 * claim: the raw methods resolve to the FFI plaintext union, which has no `Date`
 * arm, so reconstructing would make the declared type wrong. A runtime test
 * cannot see that claim expire. If `JsPlaintext` ever gains `Date` upstream, the
 * justification dissolves while every runtime assertion still passes; these are
 * what notice.
 */
describe('typed v3 client — the raw decrypt paths exclude Date', () => {
  /** The `data` of an awaited operation's success arm. */
  type SuccessData<Op> = Extract<Awaited<Op>, { data: unknown }>['data']

  type RawDecrypted = SuccessData<ReturnType<typeof client.decrypt>>
  type RawBulkDecrypted = SuccessData<ReturnType<typeof client.bulkDecrypt>>

  it('resolves decrypt to the FFI plaintext union, unwidened', () => {
    expectTypeOf<RawDecrypted>().toEqualTypeOf<JsPlaintext>()
    // The whole argument for the split in one assertion: no `Date` arm to
    // return one through. Widen `JsPlaintext` upstream and this fails.
    expectTypeOf<Date>().not.toExtend<RawDecrypted>()
  })

  it('resolves bulkDecrypt items to the same union, per position', () => {
    expectTypeOf<RawBulkDecrypted[number]['data']>().toEqualTypeOf<
      JsPlaintext | null | undefined
    >()
    expectTypeOf<Date>().not.toExtend<RawBulkDecrypted[number]['data']>()
  })

  it('reconstructs Date on the model path, which is handed the table', () => {
    // The contrast the boundary consists of, asserted on the type a caller
    // actually awaits (not just the `V3DecryptedModel` mapping above).
    type ModelDecrypted = SuccessData<
      ReturnType<
        typeof client.decryptModel<typeof users, { createdAt: Encrypted }>
      >
    >
    expectTypeOf<ModelDecrypted['createdAt']>().toEqualTypeOf<Date>()
  })

  it('types the table-less model path string, matching its unreconstructed runtime', () => {
    // `Decrypted<T>` — no table, no reconstruction, and the declared type says
    // so. Reconstructing here would be the lie the JSDoc describes.
    type LooseDecrypted = SuccessData<
      ReturnType<typeof client.decryptModel<{ createdAt: Encrypted }>>
    >
    expectTypeOf<LooseDecrypted['createdAt']>().toEqualTypeOf<string>()
  })
})

describe('typed v3 client — soundness', () => {
  it('rejects a hand-rolled structural table (no brand / private field)', () => {
    const fakeTable = {
      tableName: 'users',
      build: () => ({ tableName: 'users', columns: {} }),
    }
    client.encrypt('x', {
      // @ts-expect-error - a structural object is not a registered branded v3 table
      table: fakeTable,
      column: users.email,
    })
  })

  it('rejects a column whose domain is not present in the table', () => {
    // Plaintext is a string (valid for every `users` column domain) so the only
    // error is the column itself failing the `ColumnsOf<typeof users>` constraint.
    client.encrypt('x', {
      table: users,
      // @ts-expect-error - integer_ord column from `other` is not in ColumnsOf<typeof users>
      column: other.weight,
    })
  })
})

declare const lockContext: { identityClaim: string[] }

describe('typed v3 client — a lock context binds exactly once', () => {
  it('offers .withLockContext() on an unbound decrypt operation', () => {
    expectTypeOf(
      client.decryptModel({ email: {} as Encrypted }, users).withLockContext,
    ).toBeFunction()
    expectTypeOf(
      client.bulkDecryptModels([{ email: {} as Encrypted }], users)
        .withLockContext,
    ).toBeFunction()
  })

  it('drops .withLockContext() once bound positionally', () => {
    const op = client.decryptModel(
      { email: {} as Encrypted },
      users,
      lockContext,
    )
    // @ts-expect-error - already lock-bound; binding twice throws at runtime
    op.withLockContext(lockContext)

    const bulk = client.bulkDecryptModels(
      [{ email: {} as Encrypted }],
      users,
      lockContext,
    )
    // @ts-expect-error - already lock-bound; binding twice throws at runtime
    bulk.withLockContext(lockContext)
  })

  it('drops .withLockContext() once bound by chaining', () => {
    const op = client
      .decryptModel({ email: {} as Encrypted }, users)
      .withLockContext(lockContext)
    // @ts-expect-error - already lock-bound; binding twice throws at runtime
    op.withLockContext(lockContext)
  })

  it('keeps .audit() available after binding', () => {
    expectTypeOf(
      client.decryptModel({ email: {} as Encrypted }, users, lockContext).audit,
    ).toBeFunction()
  })
})

/**
 * The overload split that makes a double bind a compile error must not also
 * reject an OPTIONAL lock context. `decryptModel(row, table, session?.lc)` —
 * where the context is `LockContextInput | undefined` — is the ordinary shape
 * for code that decrypts identity-bound rows only for signed-in users. It
 * compiled against the single optional parameter this replaced, and nothing
 * about binding-once requires breaking it: `undefined` binds nothing.
 */
describe('typed v3 client — an optional lock context still type-checks', () => {
  it('accepts LockContextInput | undefined positionally', () => {
    expectTypeOf(client.decryptModel).toBeCallableWith(
      { email: {} as Encrypted },
      users,
      undefined,
    )
    expectTypeOf(client.bulkDecryptModels).toBeCallableWith(
      [{ email: {} as Encrypted }],
      users,
      undefined,
    )
  })

  it('accepts a union-typed context without narrowing at the call site', () => {
    const maybe: typeof lockContext | undefined = undefined
    expectTypeOf(client.decryptModel).toBeCallableWith(
      { email: {} as Encrypted },
      users,
      maybe,
    )
  })
})
