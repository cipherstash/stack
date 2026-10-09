import type { JsPlaintext } from '@cipherstash/protect-ffi'
import { describe, expectTypeOf, it } from 'vitest'
import type {
  BatchEncryptQueryOperation,
  BulkEncryptModelsOperation,
  EncryptionClient,
  EncryptModelOperation,
  EncryptOperation,
  EncryptQueryOperation,
} from '@/encryption'
// Everything comes from the single `@cipherstash/stack/v3` surface (re-exported
// from src/encryption/v3.ts), exercising the re-export at the same time.
import {
  encryptedTable,
  types,
  type V3DecryptedModel,
  type V3EncryptedModel,
} from '@/encryption/v3'
import type { JsonDocument } from '@/eql/v3/columns'
import type {
  Encrypted,
  EncryptQueryArgs,
  EncryptQueryOptions,
  QueryTermInput,
} from '@/types'

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

/**
 * What each method RETURNS, on the interface. The cases above pin what the
 * methods accept, the `V3EncryptedModel` / `V3DecryptedModel` mappings, and the
 * single-model decrypt `data`; these add the operation types and the bulk and
 * positional-lock-context `data`.
 *
 * Like everything in this file they run against `declare const client`, so
 * they check `EncryptionClient<S>`'s declared signatures — NOT
 * `createEncryptionClient`'s construction. That the factory's object literal
 * satisfies the interface is checked by `tsc` on `src` (it is annotated
 * `EncryptionClient<S>`). `typed-client-v3.test.ts` checks the factory at
 * runtime: that the encrypt methods forward their arguments to the native
 * client unchanged and return its operation, and that the model decrypt paths
 * reconstruct `Date` columns. It does not check that a native operation
 * resolves to the declared type — that needs live credentials.
 */
describe('typed v3 client — each method resolves to its precise operation', () => {
  /** The `data` of an awaited operation's success arm. */
  type SuccessData<Op> = Extract<Awaited<Op>, { data: unknown }>['data']

  it('encrypt returns an EncryptOperation', () => {
    expectTypeOf(
      client.encrypt('a@b.com', { table: users, column: users.email }),
    ).toEqualTypeOf<EncryptOperation>()
  })

  it('encryptQuery returns the scalar operation for (value, opts) and the batch one for terms', () => {
    expectTypeOf(
      client.encryptQuery('a@b.com', { table: users, column: users.email }),
    ).toEqualTypeOf<EncryptQueryOperation>()
    expectTypeOf(
      client.encryptQuery([
        { value: 'a@b.com', table: users, column: users.email },
      ]),
    ).toEqualTypeOf<BatchEncryptQueryOperation>()
  })

  it('encryptModel / bulkEncryptModels return operations over the precise encrypted model', () => {
    type Row = { id: string; email: string }
    expectTypeOf(
      client.encryptModel({ id: 'u1', email: 'a@b.com' }, users),
    ).toEqualTypeOf<
      EncryptModelOperation<V3EncryptedModel<typeof users, Row>>
    >()

    const bulk = client.bulkEncryptModels(
      [{ id: 'u1', email: 'a@b.com' }],
      users,
    )
    expectTypeOf(bulk).toEqualTypeOf<
      BulkEncryptModelsOperation<V3EncryptedModel<typeof users, Row>>
    >()
    expectTypeOf<SuccessData<typeof bulk>>().toEqualTypeOf<
      Array<{ id: string; email: Encrypted }>
    >()
  })

  it('a positional lock context keeps the precise decrypted model', () => {
    type EncRow = { id: string; email: Encrypted; createdAt: Encrypted }
    const bound = client.decryptModel({} as EncRow, users, lockContext)
    expectTypeOf<SuccessData<typeof bound>>().toEqualTypeOf<{
      id: string
      email: string
      createdAt: Date
    }>()
  })

  it('bulkDecryptModels resolves to an array of the table plaintext model, or Decrypted<T>[] without a table', () => {
    type EncRow = { id: string; email: Encrypted; createdAt: Encrypted }
    const rows = [] as EncRow[]

    expectTypeOf<
      SuccessData<
        ReturnType<typeof client.bulkDecryptModels<typeof users, EncRow>>
      >
    >().toEqualTypeOf<Array<{ id: string; email: string; createdAt: Date }>>()
    const bound = client.bulkDecryptModels(rows, users, lockContext)
    expectTypeOf<SuccessData<typeof bound>>().toEqualTypeOf<
      Array<{ id: string; email: string; createdAt: Date }>
    >()
    expectTypeOf<
      SuccessData<
        ReturnType<typeof client.bulkDecryptModels<EncRow>>
      >[number]['createdAt']
    >().toEqualTypeOf<string>()
  })
})

/**
 * The native `encryptQuery`'s argument list, as the wrapper forwards it with
 * `...args`. It is a tuple union so the one call the runtime rejects by
 * throwing — a scalar with no options — does not compile, while both real
 * forms still forward unchanged.
 */
describe('EncryptQueryArgs — a scalar needs its options, a batch takes none', () => {
  it('accepts (value, opts) and (terms)', () => {
    expectTypeOf<[string, EncryptQueryOptions]>().toExtend<EncryptQueryArgs>()
    expectTypeOf<[QueryTermInput[]]>().toExtend<EncryptQueryArgs>()
  })

  it('rejects a scalar without options, and bare values posing as terms', () => {
    expectTypeOf<[string]>().not.toExtend<EncryptQueryArgs>()
    expectTypeOf<[string[]]>().not.toExtend<EncryptQueryArgs>()
  })

  it('rejects a scalar without options on the public client', () => {
    // @ts-expect-error - a scalar query needs { table, column }
    client.encryptQuery('a@b.com')
  })
})

/**
 * A `types.Json` document may hold `null` array elements. The FFI's
 * `JsPlaintext[]` has no `null` element, so the encrypt paths take
 * `PlaintextInput`, which does. These pin that a caller reaches every encrypt
 * path with such a document through the public client, with no cast.
 */
const documents = encryptedTable('documents', {
  body: types.Json('body'),
})

declare const docClient: EncryptionClient<readonly [typeof documents]>

describe('typed v3 client — a JSON document with null array elements needs no cast', () => {
  const doc = { tags: ['staff', null] }

  it('encrypt accepts it', () => {
    docClient.encrypt(doc, { table: documents, column: documents.body })
  })

  it('encryptQuery accepts it as a searchableJson needle', () => {
    docClient.encryptQuery(doc, {
      table: documents,
      column: documents.body,
      queryType: 'searchableJson',
    })
  })

  it('bulkEncrypt accepts it', () => {
    docClient.bulkEncrypt([{ id: '1', plaintext: doc }, { plaintext: null }], {
      table: documents,
      column: documents.body,
    })
  })
})

/**
 * `encrypt` short-circuits a `null` plaintext to a `null` result rather than
 * encrypting it (DB NULL semantics). Only a `types.Json` column's plaintext
 * type admits `null` (its document type is `null | JsonValue[] | {…}`), so for
 * that column the result's `data` must admit `null` too — otherwise
 * `result.data.c` compiles and throws. A value the compiler knows is non-null
 * keeps the plain `Encrypted`, so callers that cannot pass `null` see no change.
 */
declare const maybeDoc: JsonDocument

describe('typed v3 client — encrypt result admits null exactly when the plaintext can be null', () => {
  type SuccessData<Op> = Extract<Awaited<Op>, { data: unknown }>['data']
  const docOpts = { table: documents, column: documents.body }

  it('a literal null on a Json column resolves to Encrypted | null', () => {
    const op = docClient.encrypt(null, docOpts)
    expectTypeOf<SuccessData<typeof op>>().toEqualTypeOf<Encrypted | null>()
  })

  it('a value typed JsonDocument resolves to Encrypted | null', () => {
    const op = docClient.encrypt(maybeDoc, docOpts)
    expectTypeOf<SuccessData<typeof op>>().toEqualTypeOf<Encrypted | null>()
  })

  it('a non-null document resolves to Encrypted', () => {
    const op = docClient.encrypt({ tags: ['staff', null] }, docOpts)
    expectTypeOf<SuccessData<typeof op>>().toEqualTypeOf<Encrypted>()
  })

  it('a scalar column with a string is unchanged: Encrypted', () => {
    const op = client.encrypt('a@b.com', { table: users, column: users.email })
    expectTypeOf<SuccessData<typeof op>>().toEqualTypeOf<Encrypted>()
  })

  it('.withLockContext() carries the same result type', () => {
    const nullable = docClient
      .encrypt(null, docOpts)
      .withLockContext(lockContext)
    expectTypeOf<
      SuccessData<typeof nullable>
    >().toEqualTypeOf<Encrypted | null>()
    const typed = docClient
      .encrypt(maybeDoc, docOpts)
      .withLockContext(lockContext)
    expectTypeOf<SuccessData<typeof typed>>().toEqualTypeOf<Encrypted | null>()
    const nonNull = docClient
      .encrypt({ tags: ['staff'] }, docOpts)
      .withLockContext(lockContext)
    expectTypeOf<SuccessData<typeof nonNull>>().toEqualTypeOf<Encrypted>()
    const scalar = client
      .encrypt('a@b.com', { table: users, column: users.email })
      .withLockContext(lockContext)
    expectTypeOf<SuccessData<typeof scalar>>().toEqualTypeOf<Encrypted>()
  })

  it('.audit() carries the same result type, before and after binding', () => {
    const audited = docClient.encrypt(null, docOpts).audit({ metadata: {} })
    expectTypeOf<
      SuccessData<typeof audited>
    >().toEqualTypeOf<Encrypted | null>()
    const bound = docClient
      .encrypt(null, docOpts)
      .withLockContext(lockContext)
      .audit({ metadata: {} })
    expectTypeOf<SuccessData<typeof bound>>().toEqualTypeOf<Encrypted | null>()
  })

  it('explicit <Table, Col> type arguments still compile, typed from the column', () => {
    const doc = docClient.encrypt<typeof documents, typeof documents.body>(
      maybeDoc,
      docOpts,
    )
    expectTypeOf<SuccessData<typeof doc>>().toEqualTypeOf<Encrypted | null>()
    const scalar = client.encrypt<typeof users, typeof users.email>('a@b.com', {
      table: users,
      column: users.email,
    })
    expectTypeOf<SuccessData<typeof scalar>>().toEqualTypeOf<Encrypted>()
  })

  it('execute() resolves to the same type as awaiting', () => {
    const op = docClient.encrypt(maybeDoc, docOpts)
    expectTypeOf<
      SuccessData<ReturnType<typeof op.execute>>
    >().toEqualTypeOf<Encrypted | null>()
  })
})
