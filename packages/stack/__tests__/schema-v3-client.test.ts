import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { Encryption } from '@/index'
import {
  encryptedBoolColumn,
  encryptedDateColumn,
  encryptedInt4OrdColumn,
  encryptedInt8Column,
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
  externalId: encryptedInt8Column('external_id'),
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

  it('round-trips a representative int8 storage domain (string plaintext)', async () => {
    // int8 domains use `string` plaintext until the native FFI supports bigint
    // I/O. `string` is lossless across the full int8 range (this value exceeds
    // Number.MAX_SAFE_INTEGER); `cast_as: big_int` handles server-side casting.
    const int8Encrypted = unwrapResult(
      await protectClient.encrypt('1234567890123456789', {
        table: users,
        column: users.externalId,
      }),
    )
    expect(unwrapResult(await protectClient.decrypt(int8Encrypted))).toBe(
      '1234567890123456789',
    )
  }, 30000)

  it('round-trips a representative date storage domain', async () => {
    const day = new Date('2026-07-01T00:00:00.000Z')
    const dateEncrypted = unwrapResult(
      await protectClient.encrypt(day, {
        table: users,
        column: users.createdOn,
      }),
    )
    // Assertion pending live verification: `decrypt` has no `castAs` context, so
    // whether a `date` domain returns a `Date` or an ISO string is FFI-dependent.
    // If this returns a string, that is a separate pre-existing gap to handle as
    // a follow-up (client-side Date reconstruction or a string assertion).
    expect(unwrapResult(await protectClient.decrypt(dateEncrypted))).toEqual(
      day,
    )
  }, 30000)
})
