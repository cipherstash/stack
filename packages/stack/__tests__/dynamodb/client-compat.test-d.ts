/**
 * Type-level contract for `encryptedDynamoDB` (#657).
 *
 * The runtime `*.test.ts` suites are NOT typechecked (see the comment in
 * `vitest.config.ts`), which is exactly how an M1-class regression slips
 * through: `encryptedDynamoDB` rejecting the `TypedEncryptionClient` that
 * `EncryptionV3` returns compiles nowhere and fails nothing, because the live
 * suite that would have caught it is only ever *executed*.
 *
 * So the claims the adapter's own docs make — both client shapes accepted with
 * no cast, both wire versions accepted on all four methods, `.audit()` chains,
 * awaiting yields a discriminated Result — are locked here, where `tsc` runs.
 */
import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptedDynamoDBInstance } from '@/dynamodb'
import { encryptedDynamoDB } from '@/dynamodb'
import type { EncryptionClient } from '@/encryption'
import type { EncryptionV3 } from '@/encryption/v3'
import { encryptedTable as encryptedTableV3, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'

const usersV3 = encryptedTableV3('users_v3', {
  email: types.TextEq('email'), // equality → __source + __hmac
  name: types.Text('name'), // storage only → __source
  age: types.IntegerOrd('age'), // ordering, no HMAC → __source
  meta: types.Json('meta'), // ste_vec array → __source
})

const usersV2 = encryptedTableV2('users_v2', {
  email: encryptedColumn('email').equality(),
})

// Exercises the INNERMOST `true` arm of `HasSearchTerm` (types.ts): a text
// domain that is BOTH equality- and order/range-capable — text equality is
// always HMAC-based, so it mints `__hmac`. `usersV3.age` (IntegerOrd) reaches
// the same conditional but over `number`, taking the `false` arm; without a
// text-ordering column here that `true` arm had no type-level witness.
const searchV3 = encryptedTableV3('search_v3', {
  title: types.TextOrd('title'), // equality + orderAndRange over string → __source + __hmac
  bio: types.TextMatch('bio'), // free-text only, no equality → __source, NO __hmac
})

type V3Model = { pk: string; email?: string; age?: number; role?: string }

// The two client shapes. `EncryptionV3` returns a `TypedEncryptionClient`
// parameterised by its own schema tuple; `Encryption` returns the nominal
// `EncryptionClient`. Both must be accepted by the factory WITHOUT a cast.
declare const typedClient: Awaited<
  ReturnType<typeof EncryptionV3<readonly [typeof usersV3]>>
>
declare const nominalClient: EncryptionClient

describe('encryptedDynamoDB accepts both client shapes without a cast', () => {
  it('accepts the typed client from EncryptionV3', () => {
    expectTypeOf(encryptedDynamoDB).toBeCallableWith({
      encryptionClient: typedClient,
    })
    expectTypeOf(
      encryptedDynamoDB({ encryptionClient: typedClient }),
    ).toEqualTypeOf<EncryptedDynamoDBInstance>()
  })

  it('accepts the nominal EncryptionClient', () => {
    expectTypeOf(encryptedDynamoDB).toBeCallableWith({
      encryptionClient: nominalClient,
    })
    expectTypeOf(
      encryptedDynamoDB({ encryptionClient: nominalClient }),
    ).toEqualTypeOf<EncryptedDynamoDBInstance>()
  })

  it('rejects a bare object that is not a client', () => {
    encryptedDynamoDB({
      // @ts-expect-error - not an encryption client
      encryptionClient: { nope: true },
    })
  })
})

const dynamo = encryptedDynamoDB({ encryptionClient: typedClient })

describe('all four methods accept both a v3 and a v2 table', () => {
  it('encryptModel', () => {
    expectTypeOf(dynamo.encryptModel).toBeCallableWith(
      { pk: 'a', email: 'a@b.com' },
      usersV3,
    )
    expectTypeOf(dynamo.encryptModel).toBeCallableWith(
      { pk: 'a', email: 'a@b.com' },
      usersV2,
    )
  })

  it('bulkEncryptModels', () => {
    expectTypeOf(dynamo.bulkEncryptModels).toBeCallableWith(
      [{ pk: 'a', email: 'a@b.com' }],
      usersV3,
    )
    expectTypeOf(dynamo.bulkEncryptModels).toBeCallableWith(
      [{ pk: 'a', email: 'a@b.com' }],
      usersV2,
    )
  })

  it('decryptModel', () => {
    expectTypeOf(dynamo.decryptModel).toBeCallableWith(
      { pk: 'a', email__source: 'ct' },
      usersV3,
    )
    expectTypeOf(dynamo.decryptModel).toBeCallableWith(
      { pk: 'a', email__source: 'ct' },
      usersV2,
    )
  })

  it('bulkDecryptModels', () => {
    expectTypeOf(dynamo.bulkDecryptModels).toBeCallableWith(
      [{ pk: 'a', email__source: 'ct' }],
      usersV3,
    )
    expectTypeOf(dynamo.bulkDecryptModels).toBeCallableWith(
      [{ pk: 'a', email__source: 'ct' }],
      usersV2,
    )
  })

  it('rejects a bare object as a table', () => {
    dynamo.encryptModel(
      { pk: 'a' },
      // @ts-expect-error - a plain object is not an encrypted table
      { email: 'not-a-table' },
    )
  })
})

describe('the v3 overload types the DynamoDB storage split', () => {
  it('replaces a declared column with __source, and mints __hmac only for equality', async () => {
    const result = await dynamo.encryptModel(
      { pk: 'a', email: 'a@b.com', age: 3, role: 'admin' },
      usersV3,
    )
    if (result.failure) return

    // Equality domain: ciphertext + the queryable HMAC term.
    expectTypeOf(result.data.email__source).toEqualTypeOf<string>()
    expectTypeOf(result.data.email__hmac).toEqualTypeOf<string | undefined>()
    // Ordering domain: ciphertext only — `op` has no DynamoDB query surface.
    expectTypeOf(result.data.age__source).toEqualTypeOf<string>()
    expectTypeOf(result.data).not.toHaveProperty('age__hmac')
    // The plaintext key is GONE — typing it as present is the defect this fixes.
    expectTypeOf(result.data).not.toHaveProperty('email')
    // Non-schema keys pass through untouched (pk / sk / GSI attributes).
    expectTypeOf(result.data.pk).toEqualTypeOf<string>()
    expectTypeOf(result.data.role).toEqualTypeOf<string>()
  })

  it('types a JSON document as its stored ste_vec entries plus KeyHeader', async () => {
    const result = await dynamo.encryptModel(
      { pk: 'a', meta: { a: 1 } },
      usersV3,
    )
    if (result.failure) return

    // A SteVec document is stored as `{ h, sv }` — the entries plus the
    // per-document KeyHeader `h` that protect-ffi 0.30 decrypt requires.
    expectTypeOf(result.data.meta__source).toEqualTypeOf<{
      h: unknown
      sv: unknown[]
    }>()
    expectTypeOf(result.data).not.toHaveProperty('meta__hmac')
  })

  it('applies the same storage split to the bulk return type', async () => {
    const result = await dynamo.bulkEncryptModels(
      [{ pk: 'a', email: 'a@b.com', age: 3 }],
      usersV3,
    )
    if (result.failure) return

    expectTypeOf(result.data[0].email__source).toEqualTypeOf<string>()
    expectTypeOf(result.data[0].email__hmac).toEqualTypeOf<string | undefined>()
    expectTypeOf(result.data[0].age__source).toEqualTypeOf<string>()
    expectTypeOf(result.data[0]).not.toHaveProperty('email')
  })

  it('folds bulk stored attributes back to plaintext on decrypt', async () => {
    const result = await dynamo.bulkDecryptModels(
      [{ pk: 'a', email__source: 'ct', email__hmac: 'hm' }],
      usersV3,
    )
    if (result.failure) return

    expectTypeOf(result.data[0].email).toEqualTypeOf<string>()
    expectTypeOf(result.data[0]).not.toHaveProperty('email__source')
  })

  it('rejects a field whose type does not match its column domain', () => {
    // @ts-expect-error - `email` is a text domain, not a number
    dynamo.encryptModel({ pk: 'a', email: 42 }, usersV3)
    // @ts-expect-error - `age` is an integer domain, not a string
    dynamo.encryptModel({ pk: 'a', age: 'not-a-number' }, usersV3)
  })

  it('folds the stored attributes back to plaintext on decrypt', async () => {
    const result = await dynamo.decryptModel(
      { pk: 'a', email__source: 'ct', email__hmac: 'hm', role: 'admin' },
      usersV3,
    )
    if (result.failure) return

    expectTypeOf(result.data.email).toEqualTypeOf<string>()
    // The query term is not data — it does not survive the read.
    expectTypeOf(result.data).not.toHaveProperty('email__hmac')
    expectTypeOf(result.data).not.toHaveProperty('email__source')
    expectTypeOf(result.data.pk).toEqualTypeOf<string>()
    expectTypeOf(result.data.role).toEqualTypeOf<string>()
  })

  it('round-trips a declared model shape', async () => {
    const model: V3Model = { pk: 'a', email: 'a@b.com', role: 'admin' }
    const encrypted = await dynamo.encryptModel(model, usersV3)
    if (encrypted.failure) return

    expectTypeOf(dynamo.decryptModel).toBeCallableWith(encrypted.data, usersV3)
  })
})

describe('a text-ordering domain reaches the HasSearchTerm `true` arm', () => {
  it('mints __hmac for a text equality+ordering column, but not for free-text-only', async () => {
    const result = await dynamo.encryptModel(
      { pk: 'a', title: 'Hello', bio: 'about me' },
      searchV3,
    )
    if (result.failure) return

    // TextOrd is equality- AND order/range-capable over `string`: the innermost
    // `[PlaintextForColumn<C>] extends [string] ? true : false` resolves `true`,
    // so the queryable HMAC term is present. This is the arm no prior column
    // instantiated — `usersV3.age` (IntegerOrd) takes the `false` (number) arm.
    expectTypeOf(result.data.title__source).toEqualTypeOf<string>()
    expectTypeOf(result.data.title__hmac).toEqualTypeOf<string | undefined>()

    // A free-text-only domain (`TextMatch`) is NOT equality-capable, so it never
    // reaches the ordering/text arms and writes no HMAC term — the distinct,
    // adjacent behaviour that makes the `true` arm meaningful.
    expectTypeOf(result.data.bio__source).toEqualTypeOf<string>()
    expectTypeOf(result.data).not.toHaveProperty('bio__hmac')
  })
})

describe('decrypt passes through suffixed keys whose base names no column', () => {
  it('folds a declared column but leaves unrelated __hmac / __source keys intact', async () => {
    // `email` IS a declared column; `legit` and `img` are NOT. A stored item can
    // legitimately carry a customer attribute that merely ends in `__hmac`
    // (an app-level signature) or `__source` (a renamed/foreign column) — the
    // runtime read path preserves both, and these two `DecryptedAttributes` arms
    // type that: a suffixed key whose base names no column is returned untouched.
    const result = await dynamo.decryptModel(
      {
        pk: 'a',
        email__source: 'ct',
        email__hmac: 'hm',
        legit__hmac: 'sig',
        img__source: 'raw',
      },
      usersV3,
    )
    if (result.failure) return

    // Declared column: `email__source` folds to `email`, `email__hmac` (its base
    // IS a column) is dropped as a query term.
    expectTypeOf(result.data.email).toEqualTypeOf<string>()
    expectTypeOf(result.data).not.toHaveProperty('email__source')
    expectTypeOf(result.data).not.toHaveProperty('email__hmac')

    // Non-column suffixed keys: neither folded nor dropped — the two "names no
    // column" arms. `legit__hmac`'s base is not a column, so unlike `email__hmac`
    // it survives; `img__source`'s base is not a column, so unlike `email__source`
    // it is NOT folded to `img`.
    expectTypeOf(result.data.legit__hmac).toEqualTypeOf<string>()
    expectTypeOf(result.data.img__source).toEqualTypeOf<string>()
    expectTypeOf(result.data).not.toHaveProperty('img')

    // Ordinary passthrough attribute, for contrast.
    expectTypeOf(result.data.pk).toEqualTypeOf<string>()
  })
})

describe('the v2 overload still returns the input model', () => {
  it('keeps an existing v2 caller compiling unchanged', async () => {
    const result = await dynamo.encryptModel<{ pk: string; email?: string }>(
      { pk: 'a', email: 'a@b.com' },
      usersV2,
    )
    if (result.failure) return

    expectTypeOf(result.data).toEqualTypeOf<{ pk: string; email?: string }>()
  })
})

describe('operations chain and resolve', () => {
  it('.audit() returns the operation so it stays chainable', () => {
    const op = dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV3)
    expectTypeOf(op.audit({ metadata: { sub: 'u1' } })).toEqualTypeOf<
      typeof op
    >()
  })

  it('awaiting yields a discriminated Result', async () => {
    const result = await dynamo.encryptModel(
      { pk: 'a', email: 'a@b.com' },
      usersV3,
    )

    if (result.failure) {
      expectTypeOf(result.failure.message).toEqualTypeOf<string>()
      // The success arm is not reachable in this branch — `data` is not even a
      // property of the failure member, which is the discrimination working.
      expectTypeOf(result).not.toHaveProperty('data')
      return
    }

    // ...and the failure arm is unreachable in this one.
    expectTypeOf(result.failure).toEqualTypeOf<undefined>()
    expectTypeOf(result.data.email__source).toEqualTypeOf<string>()
  })
})
