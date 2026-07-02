import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { typedClient } from '@/encryption/v3'
import { Encryption } from '@/index'
import {
  encryptedBoolColumn,
  encryptedDateColumn,
  encryptedInt4OrdColumn,
  encryptedTable,
  encryptedTextColumn,
  encryptedTextEqColumn,
  encryptedTextMatchColumn,
  encryptedTextSearchColumn,
  encryptedTimestamptzColumn,
} from '@/schema/v3'
import { unwrapResult } from './fixtures'

const users = encryptedTable('schema_v3_client_users', {
  email: encryptedTextSearchColumn('email'),
  age: encryptedInt4OrdColumn('age'),
  nickname: encryptedTextEqColumn('nickname'),
  body: encryptedTextMatchColumn('body'),
  notes: encryptedTextColumn('notes'),
  active: encryptedBoolColumn('active'),
  // camelCase JS property → snake_case DB name on purpose: the model path must
  // match models by JS property (`createdOn`) yet address the FFI/config by DB
  // name (`created_on`). The round-trip tests below exercise that mapping.
  createdOn: encryptedDateColumn('created_on'),
  occurredAt: encryptedTimestamptzColumn('occurred_at'),
})

const LIVE_CIPHERSTASH_ENABLED = Boolean(
  process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)

const describeLive = LIVE_CIPHERSTASH_ENABLED ? describe : describe.skip

describeLive('eql_v3 client integration', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [users] })
  })

  it('encrypts and decrypts a text_search column', async () => {
    const encrypted = unwrapResult(
      await protectClient.encrypt('ada@example.com', {
        table: users,
        column: users.email,
      }),
    )

    expect(encrypted).toMatchObject({
      i: { t: 'schema_v3_client_users', c: 'email' },
      v: 2,
    })
    expect(encrypted).toHaveProperty('c')
    expect(encrypted).toHaveProperty('hm')
    expect(encrypted).toHaveProperty('bf')
    expect(encrypted).toHaveProperty('ob')

    const decrypted = unwrapResult(await protectClient.decrypt(encrypted))
    expect(decrypted).toBe('ada@example.com')
  }, 30000)

  it('auto-infers equality query terms for text_search columns', async () => {
    const queryTerm = unwrapResult(
      await protectClient.encryptQuery('ada@example.com', {
        table: users,
        column: users.email,
      }),
    )

    expect(queryTerm).toMatchObject({
      i: { t: 'schema_v3_client_users', c: 'email' },
      v: 2,
    })
    expect(queryTerm).toHaveProperty('hm')
    expect(queryTerm).not.toHaveProperty('c')
  }, 30000)

  it('encrypts explicit freeTextSearch and orderAndRange query terms', async () => {
    const matchTerm = unwrapResult(
      await protectClient.encryptQuery('Ada Lovelace', {
        table: users,
        column: users.email,
        queryType: 'freeTextSearch',
      }),
    )

    const orderTerm = unwrapResult(
      await protectClient.encryptQuery('ada@example.com', {
        table: users,
        column: users.email,
        queryType: 'orderAndRange',
      }),
    )

    expect(matchTerm).toHaveProperty('bf')
    expect(matchTerm).not.toHaveProperty('c')
    expect(orderTerm).toHaveProperty('ob')
    expect(orderTerm).not.toHaveProperty('c')
  }, 30000)

  it('encrypts and decrypts storage-only v3 columns', async () => {
    const encryptedText = unwrapResult(
      await protectClient.encrypt('private note', {
        table: users,
        column: users.notes,
      }),
    )
    expect(encryptedText).toMatchObject({
      i: { t: 'schema_v3_client_users', c: 'notes' },
      v: 2,
    })
    expect(encryptedText).toHaveProperty('c')
    expect(encryptedText).not.toHaveProperty('hm')
    expect(encryptedText).not.toHaveProperty('bf')
    expect(encryptedText).not.toHaveProperty('ob')
    expect(unwrapResult(await protectClient.decrypt(encryptedText))).toBe(
      'private note',
    )

    const encryptedBool = unwrapResult(
      await protectClient.encrypt(true, {
        table: users,
        column: users.active,
      }),
    )
    expect(encryptedBool).toHaveProperty('c')
    expect(unwrapResult(await protectClient.decrypt(encryptedBool))).toBe(true)
  }, 30000)

  it('encrypts equality and order query terms for typed v3 columns', async () => {
    const equalityTerm = unwrapResult(
      await protectClient.encryptQuery('ada', {
        table: users,
        column: users.nickname,
      }),
    )
    expect(equalityTerm).toHaveProperty('hm')
    expect(equalityTerm).not.toHaveProperty('c')

    const orderTerm = unwrapResult(
      await protectClient.encryptQuery(37, {
        table: users,
        column: users.age,
        queryType: 'orderAndRange',
      }),
    )
    expect(orderTerm).toHaveProperty('ob')
    expect(orderTerm).not.toHaveProperty('c')
  }, 30000)

  it('encrypts free-text terms for text_match columns', async () => {
    const encrypted = unwrapResult(
      await protectClient.encrypt('Ada Lovelace wrote notes', {
        table: users,
        column: users.body,
      }),
    )
    expect(encrypted).toHaveProperty('c')
    expect(encrypted).toHaveProperty('bf')
    expect(encrypted).not.toHaveProperty('hm')
    expect(encrypted).not.toHaveProperty('ob')

    const matchTerm = unwrapResult(
      await protectClient.encryptQuery('Lovelace', {
        table: users,
        column: users.body,
        queryType: 'freeTextSearch',
      }),
    )
    expect(matchTerm).toHaveProperty('bf')
    expect(matchTerm).not.toHaveProperty('c')
  }, 30000)

  // int8 (bigint) storage domains are omitted from the v3 SDK until the native
  // protect-ffi supports lossless bigint round-tripping — a `bigint` fails JSON
  // serialization and a `string` is rejected for a `big_int` column. Re-add a
  // round-trip test alongside the domain builders when the FFI lands.

  // A `date` domain decrypts to an ISO 8601 string from the native FFI, so the
  // single-value `decrypt` path returns a string (a lone ciphertext carries no
  // column context). The typed client's `decryptModel` reconstructs a real
  // `Date` from the encrypt-config `cast_as` (`reconstructRow`), keyed by the
  // JS property (`createdOn`) even though the DB column is `created_on`.
  it('round-trips a representative date storage domain via decryptModel', async () => {
    const typed = typedClient(protectClient, users)
    // Zero milliseconds so the FFI dropping sub-second precision (`...00Z` vs
    // `...000Z`) does not perturb the reconstructed instant.
    const day = new Date('2026-07-01T00:00:00.000Z')

    // Encrypt via the single-value path (the proven route for a `Date` domain),
    // then decrypt through the model path so `reconstructRow` rebuilds a `Date`
    // from the encrypt-config `cast_as`.
    const dateEncrypted = unwrapResult(
      await protectClient.encrypt(day, {
        table: users,
        column: users.createdOn,
      }),
    )
    // Guard against a false pass: the value must be an actual ciphertext, not a
    // plaintext `Date` that would trivially satisfy the assertions below.
    expect(dateEncrypted).toHaveProperty('c')

    const decrypted = unwrapResult(
      await typed.decryptModel({ createdOn: dateEncrypted }, users),
    )
    expect(decrypted.createdOn).toBeInstanceOf(Date)
    expect(decrypted.createdOn).toEqual(day)
  }, 30000)

  // Regression: a camelCase JS property mapping to a snake_case DB column
  // (`nickname` is name==key, but `createdOn`→`created_on` is not) must be
  // ENCRYPTED by the model path — not silently passed through as plaintext
  // because the field key (`createdOn`) fails to match the DB-keyed config.
  it('encrypts a property-vs-DB-name column through encryptModel (no plaintext leak)', async () => {
    const typed = typedClient(protectClient, users)
    const day = new Date('2026-07-01T00:00:00.000Z')

    const encrypted = unwrapResult(
      await typed.encryptModel({ createdOn: day, notes: 'hello' }, users),
    )
    // The schema field must become a ciphertext (has `c`), NOT remain a Date.
    expect(encrypted.createdOn).not.toBeInstanceOf(Date)
    expect(encrypted.createdOn).toHaveProperty('c')
    expect(encrypted.notes).toHaveProperty('c')

    const decrypted = unwrapResult(await typed.decryptModel(encrypted, users))
    expect(decrypted.createdOn).toBeInstanceOf(Date)
    expect(decrypted.createdOn).toEqual(day)
    expect(decrypted.notes).toBe('hello')
  }, 30000)

  // Hygiene: `occurredAt` (a timestamptz column, camelCase property →
  // snake_case DB name `occurred_at`) was declared in the test table but never
  // asserted. Give it a real round-trip through the model path, complementing
  // the `createdOn` date case above. (`matrix-live.test.ts` is the canonical
  // generic coverage for all timestamptz tiers; this pins the named column.)
  it('round-trips a timestamptz occurredAt column through the model path', async () => {
    const typed = typedClient(protectClient, users)
    // Zero milliseconds: the FFI drops sub-second precision, so a ms-bearing
    // instant would perturb the reconstructed value.
    const moment = new Date('2026-07-01T12:34:56.000Z')

    const encrypted = unwrapResult(
      await typed.encryptModel({ occurredAt: moment, notes: 'seen' }, users),
    )
    // Must become a ciphertext, not remain a Date (no plaintext passthrough).
    expect(encrypted.occurredAt).not.toBeInstanceOf(Date)
    expect(encrypted.occurredAt).toHaveProperty('c')

    const decrypted = unwrapResult(await typed.decryptModel(encrypted, users))
    expect(decrypted.occurredAt).toBeInstanceOf(Date)
    expect(decrypted.occurredAt).toEqual(moment)
  }, 30000)
})
