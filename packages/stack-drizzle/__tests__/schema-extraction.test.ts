import { encryptedTable, types as v3Types } from '@cipherstash/stack/eql/v3'
import { integer, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { extractEncryptionSchema } from '../src/schema-extraction'
import { types } from '../src/types'

describe('extractEncryptionSchema', () => {
  it('rebuilds an equivalent eql/v3 encryptedTable from every drizzle v3 factory', () => {
    const drizzleColumns = Object.fromEntries(
      Object.entries(types).map(([factoryName, factory]) => [
        factoryName,
        factory(factoryName),
      ]),
    )
    const authoredColumns = Object.fromEntries(
      Object.entries(v3Types).map(([factoryName, factory]) => [
        factoryName,
        factory(factoryName),
      ]),
    )

    const extracted = extractEncryptionSchema(
      pgTable('users', drizzleColumns as never),
    )
    const authored = encryptedTable('users', authoredColumns as never)

    expect(extracted.build()).toStrictEqual(authored.build())
  })

  it('rebuilds an equivalent eql/v3 encryptedTable from a drizzle table', () => {
    const users = pgTable('users', {
      id: integer().primaryKey(),
      email: types.TextSearch('email'),
      age: types.IntegerOrd('age'),
    })

    const extracted = extractEncryptionSchema(users)
    const authored = encryptedTable('users', {
      email: v3Types.TextSearch('email'),
      age: v3Types.IntegerOrd('age'),
    })

    expect(extracted.build()).toStrictEqual(authored.build())
  })

  it('keeps same-named columns on different tables bound to their own v3 domains', () => {
    const accounts = pgTable('accounts', {
      email: types.TextEq('email'),
    })
    const metrics = pgTable('metrics', {
      email: types.IntegerOrd('email'),
    })

    const accountsSchema = extractEncryptionSchema(accounts)
    const metricsSchema = extractEncryptionSchema(metrics)

    expect(accountsSchema.build()).toStrictEqual(
      encryptedTable('accounts', {
        email: v3Types.TextEq('email'),
      }).build(),
    )
    expect(metricsSchema.build()).toStrictEqual(
      encryptedTable('metrics', {
        email: v3Types.IntegerOrd('email'),
      }).build(),
    )
  })

  it('uses the JS property key while preserving distinct SQL column names', () => {
    const users = pgTable('users', {
      createdOn: types.Date('created_on'),
      emailAddress: types.TextEq('email_address'),
    })

    expect(extractEncryptionSchema(users).build()).toStrictEqual(
      encryptedTable('users', {
        createdOn: v3Types.Date('created_on'),
        emailAddress: v3Types.TextEq('email_address'),
      }).build(),
    )
  })

  it('uses the Drizzle column name when rebuilding fallback SQL-type columns', () => {
    const table = {
      [Symbol.for('drizzle:Name')]: 'users',
      createdOn: {
        name: 'created_on',
        getSQLType: () => 'public.eql_v3_date',
      },
    }

    expect(extractEncryptionSchema(table as never).build()).toStrictEqual(
      encryptedTable('users', {
        createdOn: v3Types.Date('created_on'),
      }).build(),
    )
  })

  it('throws when the table has no encrypted v3 columns', () => {
    const plain = pgTable('plain', { id: integer() })
    expect(() => extractEncryptionSchema(plain)).toThrow(/no encrypted v3/i)
  })

  it('throws the table-name error before checking for encrypted columns', () => {
    expect(() =>
      extractEncryptionSchema({
        secret: { getSQLType: () => 'public.eql_v3_text_eq', name: 'secret' },
      } as never),
    ).toThrow('Unable to read table name from Drizzle table.')
  })
})
