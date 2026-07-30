/**
 * Type-level contract for {@link extractEncryptionSchema} (#589).
 *
 * A Drizzle-extracted schema must be typed as precisely as the hand-authored
 * `encryptedTable({…})` it is equivalent to. Before #589 it was not: extraction
 * returned the widened `AnyV3Table`, so `InferPlaintext` over an extracted
 * schema collapsed to an index signature and every column on the insert path
 * accepted (and produced) the union of every domain's plaintext instead of its
 * own. There was no runtime bug — the runtime already recovers each column's
 * concrete builder — which is exactly why this needs a type test to hold it.
 *
 * Every assertion below is written to be equally meaningful on BOTH paths, so
 * the hand-authored surface cannot regress while the extracted one is fixed.
 */

import {
  type AnyV3Table,
  type EncryptedIntegerOrdColumn,
  type EncryptedJsonColumn,
  type EncryptedTextEqColumn,
  encryptedTable,
  type InferPlaintext,
  type JsonDocument,
  types as v3Types,
} from '@cipherstash/stack/eql/v3'
import type { Encrypted } from '@cipherstash/stack/types'
import { Encryption, type EncryptionClient } from '@cipherstash/stack/v3'
import {
  customType,
  type PgTable,
  pgTable,
  serial,
  text,
} from 'drizzle-orm/pg-core'
import { describe, expectTypeOf, it } from 'vitest'
import { extractEncryptionSchema } from '../src/schema-extraction'
import { types } from '../src/types'

// `id` and `nickname` are load-bearing, not scenery: extraction must keep only
// the encrypted (branded) columns, so the mapped type has to filter them out.
// They also cover the other half of the insert contract — a plain helper column
// must pass through the model types untouched rather than being treated as an
// encrypted one.
const users = pgTable('users', {
  id: serial('id').primaryKey(),
  nickname: text('nickname'),
  email: types.TextEq('email'),
  age: types.IntegerOrd('age'),
})

/** The hand-authored equivalent of `users`. Same columns, same domains. */
const authored = encryptedTable('users', {
  email: v3Types.TextEq('email'),
  age: v3Types.IntegerOrd('age'),
})

const extracted = extractEncryptionSchema(users)

// Consumers can legitimately erase a table's concrete column shape at module
// boundaries. Runtime extraction still sees the columns in this case, but the
// private type brand is no longer recoverable.
const widenedUsers: PgTable = users
const widenedExtracted = extractEncryptionSchema(widenedUsers)

// Runtime extraction also supports ordinary Drizzle custom columns by their
// EQL SQL domain, even though those columns never carried our private brand.
const eqlTextEq = customType<{ data: Encrypted }>({
  dataType: () => 'eql_v3_text_eq',
})
const sqlTypeFallbackUsers = pgTable('sql_type_fallback_users', {
  email: eqlTextEq('email'),
})
const fallbackExtracted = extractEncryptionSchema(sqlTypeFallbackUsers)

// A single visible brand must not make the schema look complete when another
// runtime-encrypted column is only recoverable from its SQL domain.
const mixedUsers = pgTable('mixed_users', {
  email: eqlTextEq('email'),
  age: types.IntegerOrd('age'),
})
const mixedExtracted = extractEncryptionSchema(mixedUsers)

// Real schemas rarely declare a bare column — `.notNull()` in particular is
// near-universal. Modifiers are the one place the brand could be dropped for
// SOME columns while bare ones keep working, which is why they get their own
// fixture: every other table here is bare, so a modifier-only regression would
// otherwise ship green. See the `modifiers` describe below.
const modified = pgTable('modified', {
  bare: types.TextEq('bare'),
  notNull: types.TextEq('not_null').notNull(),
  unique: types.IntegerOrd('uniq').unique(),
  chained: types.IntegerOrd('chained').notNull().unique(),
})
const modifiedExtracted = extractEncryptionSchema(modified)

// `types.Json`'s plaintext is the whole `JsonDocument` union rather than a
// scalar, so it exercises the one domain where a widened index signature and
// the precise type are easiest to confuse.
const documents = pgTable('documents', {
  id: serial('id').primaryKey(),
  doc: types.Json('doc'),
  label: types.TextEq('label'),
})
const documentsExtracted = extractEncryptionSchema(documents)
const documentsAuthored = encryptedTable('documents', {
  doc: v3Types.Json('doc'),
  label: v3Types.TextEq('label'),
})

/** The plaintext map both schemas must infer. */
type UserPlaintext = { email: string; age: number }

/** The model handed to `bulkEncryptModels`, plain helper columns included. */
const plainRows = [
  { id: 1, nickname: 'ada', email: 'ada@example.com', age: 36 },
]

/**
 * What `bulkEncryptModels` must resolve: the two encrypted columns become
 * envelopes, the two plain ones pass through with their own types.
 */
type EncryptedUserRow = {
  id: number
  nickname: string
  email: Encrypted
  age: Encrypted
}

describe('extractEncryptionSchema - plaintext inference (#589)', () => {
  it('infers the same precise plaintext map as the hand-authored table', () => {
    expectTypeOf<
      InferPlaintext<typeof authored>
    >().toEqualTypeOf<UserPlaintext>()
    expectTypeOf<
      InferPlaintext<typeof extracted>
    >().toEqualTypeOf<UserPlaintext>()
  })

  it('drops the table’s plain, non-encrypted columns', () => {
    // The `toEqualTypeOf` above already forbids extra keys; this states the
    // filtering intent directly so a failure names the actual cause.
    expectTypeOf<keyof InferPlaintext<typeof extracted>>().toEqualTypeOf<
      'email' | 'age'
    >()
  })

  it('keeps each column addressable at its concrete domain type', () => {
    // `encryptedTable()` returns `EncryptedTable<C> & C`, so the schema doubles
    // as a column accessor. Extraction returns the same intersection — that is
    // what lets `client.encrypt(v, { table, column: schema.email })` pin `v` to
    // the column's own plaintext rather than the union of every domain's.
    expectTypeOf(extracted.email).toEqualTypeOf<EncryptedTextEqColumn>()
    expectTypeOf(extracted.age).toEqualTypeOf<EncryptedIntegerOrdColumn>()
    expectTypeOf(authored.email).toEqualTypeOf<EncryptedTextEqColumn>()
    expectTypeOf(authored.age).toEqualTypeOf<EncryptedIntegerOrdColumn>()
  })
})

/**
 * Regression guard for the brand's survival through Drizzle's column modifiers.
 *
 * `pgTable()` does not hand builders through — it rebuilds each one via
 * drizzle's `BuildColumn`, which keeps only
 * `Omit<TBuilder['_'], keyof MakeColumnConfig<…> | 'brand' | 'dialect'>`. The
 * brand rides in `_` precisely so it survives that (see `EqlV3Column`), and
 * modifiers then intersect further into `_` (`NotNull<T> = T & { _: { notNull:
 * true } }`). Both steps have to preserve the symbol key.
 *
 * This is a drizzle-orm compatibility contract, not one we control: an upstream
 * change to how `BuildColumn` or `NotNull` reshape `_` could drop the brand for
 * modified columns while bare ones keep working. The runtime would not notice —
 * `getEqlV3Column` recovers builders from the runtime carrier and the SQL domain,
 * never from the type — so extraction would silently type a `.notNull()` column
 * as a plain pass-through field while still encrypting it. Nothing else in CI
 * catches that.
 */
describe('extractEncryptionSchema - drizzle column modifiers', () => {
  it('keeps modified columns in the extracted schema', () => {
    expectTypeOf<
      keyof InferPlaintext<typeof modifiedExtracted>
    >().toEqualTypeOf<'bare' | 'notNull' | 'unique' | 'chained'>()
  })

  it('keeps each modified column at its own concrete plaintext type', () => {
    expectTypeOf<InferPlaintext<typeof modifiedExtracted>>().toEqualTypeOf<{
      bare: string
      notNull: string
      unique: number
      chained: number
    }>()
  })

  it('keeps modified columns addressable at their concrete domain type', () => {
    expectTypeOf(
      modifiedExtracted.notNull,
    ).toEqualTypeOf<EncryptedTextEqColumn>()
    expectTypeOf(
      modifiedExtracted.chained,
    ).toEqualTypeOf<EncryptedIntegerOrdColumn>()
  })
})

/**
 * `types.Json` is the only domain whose plaintext is a union rather than a
 * scalar, so it is the easiest one to lose to a widened index signature without
 * any other assertion noticing.
 */
describe('extractEncryptionSchema - json domain', () => {
  it('infers JsonDocument on both paths', () => {
    type DocumentPlaintext = { doc: JsonDocument; label: string }

    expectTypeOf<
      InferPlaintext<typeof documentsExtracted>
    >().toEqualTypeOf<DocumentPlaintext>()
    expectTypeOf<
      InferPlaintext<typeof documentsAuthored>
    >().toEqualTypeOf<DocumentPlaintext>()
  })

  it('keeps the json column addressable at its concrete domain type', () => {
    expectTypeOf(documentsExtracted.doc).toEqualTypeOf<EncryptedJsonColumn>()
    expectTypeOf(
      documentsExtracted.label,
    ).toEqualTypeOf<EncryptedTextEqColumn>()
  })

  it('rejects a scalar written to a json column', async () => {
    const client = await Encryption({ schemas: [documentsExtracted] })

    expectTypeOf(client.encrypt).toBeCallableWith(
      { note: 'ok' },
      { table: documentsExtracted, column: documentsExtracted.doc },
    )
    // @ts-expect-error - JsonDocument is object | array | null, never a scalar
    client.encrypt(36, {
      table: documentsExtracted,
      column: documentsExtracted.doc,
    })
  })
})

describe('extractEncryptionSchema - unbranded table fallback', () => {
  it('preserves the widened schema type for a table annotated as PgTable', () => {
    expectTypeOf(widenedExtracted).toEqualTypeOf<AnyV3Table>()
    expectTypeOf<keyof InferPlaintext<typeof widenedExtracted>>().toEqualTypeOf<
      string | number
    >()
  })

  it('preserves the widened schema type for columns recovered by SQL type', () => {
    expectTypeOf(fallbackExtracted).toEqualTypeOf<AnyV3Table>()
    expectTypeOf<
      keyof InferPlaintext<typeof fallbackExtracted>
    >().toEqualTypeOf<string | number>()
  })

  it('still types fields as encrypted through widened model operations', async () => {
    const client = await Encryption({ schemas: [widenedExtracted] })
    const result = await client.bulkEncryptModels(
      [{ email: 'ada@example.com' }],
      widenedExtracted,
    )
    if (result.failure) throw result.failure

    expectTypeOf(result.data).toEqualTypeOf<Array<{ email: Encrypted }>>()
  })

  it('widens a mixed branded and SQL-derived schema as a complete unit', async () => {
    expectTypeOf(mixedExtracted).toEqualTypeOf<AnyV3Table>()

    const client = await Encryption({ schemas: [mixedExtracted] })
    const result = await client.bulkEncryptModels(
      [{ email: 'ada@example.com', age: 36 }],
      mixedExtracted,
    )
    if (result.failure) throw result.failure

    expectTypeOf(result.data).toEqualTypeOf<
      Array<{ email: Encrypted; age: Encrypted }>
    >()
  })
})

/**
 * The documented Drizzle flow, end to end:
 * `extractEncryptionSchema(table)` -> `Encryption({ schemas })` -> `bulkEncryptModels`.
 *
 * This is the path the issue reports as widened, so it is asserted on the real
 * factory rather than on a hand-named client type — the whole point is that the
 * concrete tuple survives from extraction through to the model types.
 *
 * These `it` bodies are type-checked, never executed: vitest's typecheck mode
 * does not run `.test-d.ts` files, and they are outside the runtime suite's
 * `include`. So `Encryption()` here needs no credentials.
 */
describe('extractEncryptionSchema - documented flow (#589)', () => {
  it('carries the extracted schema into the client tuple', async () => {
    const client = await Encryption({ schemas: [extracted] })
    expectTypeOf(client).toEqualTypeOf<
      EncryptionClient<readonly [typeof extracted]>
    >()
  })

  it('types bulkEncryptModels precisely against an extracted schema', async () => {
    const client = await Encryption({ schemas: [extracted] })
    const result = await client.bulkEncryptModels(plainRows, extracted)
    if (result.failure) throw result.failure

    expectTypeOf(result.data).toEqualTypeOf<EncryptedUserRow[]>()
  })

  it('types bulkEncryptModels precisely against the hand-authored schema', async () => {
    const client = await Encryption({ schemas: [authored] })
    const result = await client.bulkEncryptModels(plainRows, authored)
    if (result.failure) throw result.failure

    expectTypeOf(result.data).toEqualTypeOf<EncryptedUserRow[]>()
  })

  it('rejects a field typed against the wrong domain on either path', async () => {
    const onExtracted = await Encryption({ schemas: [extracted] })
    const onAuthored = await Encryption({ schemas: [authored] })
    const wrong = [{ email: 'ada@example.com', age: 'thirty-six' }]

    // This is the assertion with teeth. While extraction returned `AnyV3Table`,
    // every column's plaintext was the union of every domain's, so a `string`
    // in an `IntegerOrd` column type-checked and the mismatch only surfaced at
    // encrypt time. If that widening ever returns, the suppression below goes
    // unused and this test fails.
    // @ts-expect-error - `age` is IntegerOrd: its plaintext is number, not string
    onExtracted.bulkEncryptModels(wrong, extracted)
    // @ts-expect-error - the hand-authored path has always rejected this; it must keep doing so
    onAuthored.bulkEncryptModels(wrong, authored)
  })

  it('pins encrypt() to the addressed column’s own plaintext type', async () => {
    const client = await Encryption({ schemas: [extracted] })

    expectTypeOf(client.encrypt).toBeCallableWith('ada@example.com', {
      table: extracted,
      column: extracted.email,
    })
    expectTypeOf(client.encrypt).toBeCallableWith(36, {
      table: extracted,
      column: extracted.age,
    })
    // @ts-expect-error - the email column encrypts a string, not a number
    client.encrypt(36, { table: extracted, column: extracted.email })
  })
})
