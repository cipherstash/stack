import { describe, expectTypeOf, it } from 'vitest'
// v2 column builder — used only to prove the v3 table type rejects it.
import { encryptedColumn } from '@/schema'
import type {
  EncryptedTextSearchColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema/v3'
import { encryptedTable, encryptedTextSearchColumn } from '@/schema/v3'
import type { Encrypted } from '@/types'

describe('eql_v3 schema type inference', () => {
  it('encryptedTextSearchColumn returns an EncryptedTextSearchColumn', () => {
    const col = encryptedTextSearchColumn('email')
    expectTypeOf(col).toEqualTypeOf<EncryptedTextSearchColumn>()
  })

  it('encryptedTable exposes column builders as typed properties', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    expectTypeOf(users.email).toEqualTypeOf<EncryptedTextSearchColumn>()
    expectTypeOf(users.tableName).toBeString()
  })

  it('rejects a v2 EncryptedColumn in a v3 table (nominal private-field mismatch)', () => {
    encryptedTable('users', {
      // @ts-expect-error - a v2 EncryptedColumn is not an EncryptedTextSearchColumn
      email: encryptedColumn('email'),
    })
  })

  it('InferPlaintext maps each column to string', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
      name: encryptedTextSearchColumn('name'),
    })
    type Plaintext = InferPlaintext<typeof users>
    expectTypeOf<Plaintext>().toEqualTypeOf<{ email: string; name: string }>()
  })

  it('InferEncrypted maps each column to Encrypted', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    type Enc = InferEncrypted<typeof users>
    expectTypeOf<Enc>().toEqualTypeOf<{ email: Encrypted }>()
  })
})
