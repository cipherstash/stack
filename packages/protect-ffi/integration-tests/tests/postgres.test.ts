import 'dotenv/config'
import {
  type EncryptConfig,
  type Encrypted,
  decrypt,
  decryptBulk,
  encrypt,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'
import { Client, type QueryResult } from 'pg'
import { beforeAll, beforeEach, describe, expect, test } from 'vitest'

describe('postgres', async () => {
  const protectClient = await newClient({ encryptConfig: encryptConfig() })
  const pg = new Client()
  await pg.connect()

  // called once before all tests run
  beforeAll(async () => {
    await pg.query('DROP TABLE IF EXISTS encrypted')

    await pg.query(`
      CREATE TABLE encrypted (
        id SERIAL PRIMARY KEY,
        encrypted_text eql_v2_encrypted
      )
    `)

    await pg.query(
      "SELECT eql_v2.add_encrypted_constraint('encrypted', 'encrypted_text')",
    )

    // clean up function, called once after all tests run
    return async () => {
      await pg.query('DROP TABLE ENCRYPTED')
      await pg.end()
    }
  })

  beforeEach(async () => {
    // called once before each test run
    await pg.query('BEGIN')

    // clean up function, called once after each test run
    return async () => {
      await pg.query('ROLLBACK')
    }
  })

  test('can round-trip encrypt and decrypt', async () => {
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(protectClient, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb)',
      [ciphertext],
    )

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(
      'SELECT encrypted_text::jsonb FROM encrypted',
    )

    expect(res.rowCount).toBe(1)

    const decrypted = await decrypt(protectClient, {
      ciphertext: res.rows[0].encrypted_text,
    })

    expect(decrypted).toBe(originalPlaintext)
  })

  test('can order by an ORE index', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: 'ccc',
          column: 'email',
          table: 'users',
        },
        {
          plaintext: 'aaa',
          column: 'email',
          table: 'users',
        },
        {
          plaintext: 'bbb',
          column: 'email',
          table: 'users',
        },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(`
      SELECT encrypted_text::jsonb FROM encrypted
      ORDER BY eql_v2.order_by(encrypted_text) ASC
    `)

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_text,
      })),
    })

    expect(decrypted).toEqual(['aaa', 'bbb', 'ccc'])
  })

  test('can use a match query', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: 'aaa bbb',
          column: 'email',
          table: 'users',
        },
        {
          plaintext: 'aaa ccc',
          column: 'email',
          table: 'users',
        },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const search = await encrypt(protectClient, {
      plaintext: 'ccc',
      column: 'email',
      table: 'users',
    })

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(
      `
      SELECT encrypted_text::jsonb FROM encrypted
      WHERE encrypted_text LIKE $1::jsonb
      `,
      [search],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_text,
      })),
    })

    expect(decrypted).toEqual(['aaa ccc'])
  })

  test('can use an exact query', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: 'a',
          column: 'email',
          table: 'users',
        },
        {
          plaintext: 'b',
          column: 'email',
          table: 'users',
        },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(
      `
      SELECT encrypted_text::jsonb FROM encrypted
      WHERE encrypted_text = $1::jsonb
      `,
      [
        await encrypt(protectClient, {
          plaintext: 'b',
          column: 'email',
          table: 'users',
        }),
      ],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_text,
      })),
    })

    expect(decrypted).toEqual(['b'])
  })
})

function encryptConfig(): EncryptConfig {
  return {
    v: 1,
    tables: {
      users: {
        email: {
          indexes: {
            ore: {},
            match: {
              tokenizer: {
                kind: 'ngram',
                token_length: 3,
              },
              token_filters: [
                {
                  kind: 'downcase',
                },
              ],
              k: 6,
              m: 2048,
              include_original: false,
            },
            unique: {},
          },
        },
      },
    },
  }
}
