import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import type {
  EncryptedColumn,
  EncryptedField,
  EncryptedTable,
  EncryptedTableColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema'
import { encryptedColumn, encryptedTable } from '@/schema'
import type {
  Decrypted,
  DecryptedFields,
  Encrypted,
  EncryptedFields,
  EncryptedFromSchema,
  EncryptedReturnType,
  KeysetIdentifier,
  OtherFields,
  QueryTypeName,
} from '@/types'

describe('Type inference', () => {
  it('encryptedTable returns ProtectTable with column access', () => {
    const table = encryptedTable('users', {
      email: encryptedColumn('email'),
    })
    expectTypeOf(table.email).toMatchTypeOf<EncryptedColumn>()
    expectTypeOf(table.tableName).toBeString()
  })

  it('encryptedTable is also a ProtectTable', () => {
    const table = encryptedTable('users', {
      email: encryptedColumn('email'),
    })
    expectTypeOf(table).toMatchTypeOf<
      EncryptedTable<{ email: EncryptedColumn }>
    >()
  })

  it('encryptedColumn returns ProtectColumn', () => {
    const col = encryptedColumn('email')
    expectTypeOf(col).toMatchTypeOf<EncryptedColumn>()
  })

  it('encryptedColumn().dataType() returns ProtectColumn (for chaining)', () => {
    const col = encryptedColumn('age').dataType('number')
    expectTypeOf(col).toMatchTypeOf<EncryptedColumn>()
  })

  it('encryptedColumn().equality() returns ProtectColumn (for chaining)', () => {
    const col = encryptedColumn('email').equality()
    expectTypeOf(col).toMatchTypeOf<EncryptedColumn>()
  })

  it('Decrypted<T> maps Encrypted fields to string', () => {
    type Model = { email: Encrypted; name: string }
    type Result = Decrypted<Model>
    expectTypeOf<Result>().toMatchTypeOf<{ email: string; name: string }>()
  })

  it('EncryptedFields<T> extracts only Encrypted fields', () => {
    type Model = { email: Encrypted; name: string; age: number }
    type Result = EncryptedFields<Model>
    expectTypeOf<Result>().toMatchTypeOf<{ email: Encrypted }>()
  })

  it('OtherFields<T> extracts non-Encrypted fields', () => {
    type Model = { email: Encrypted; name: string; age: number }
    type Result = OtherFields<Model>
    expectTypeOf<Result>().toMatchTypeOf<{ name: string; age: number }>()
  })

  it('DecryptedFields<T> maps Encrypted fields to string', () => {
    type Model = { email: Encrypted; name: string }
    type Result = DecryptedFields<Model>
    expectTypeOf<Result>().toMatchTypeOf<{ email: string }>()
  })

  it('KeysetIdentifier is a union of name or id', () => {
    expectTypeOf<{ name: string }>().toMatchTypeOf<KeysetIdentifier>()
    expectTypeOf<{ id: string }>().toMatchTypeOf<KeysetIdentifier>()
  })

  it('QueryTypeName includes expected values', () => {
    expectTypeOf<'equality'>().toMatchTypeOf<QueryTypeName>()
    expectTypeOf<'freeTextSearch'>().toMatchTypeOf<QueryTypeName>()
    expectTypeOf<'orderAndRange'>().toMatchTypeOf<QueryTypeName>()
    expectTypeOf<'searchableJson'>().toMatchTypeOf<QueryTypeName>()
    expectTypeOf<'steVecSelector'>().toMatchTypeOf<QueryTypeName>()
    expectTypeOf<'steVecValueSelector'>().toMatchTypeOf<QueryTypeName>()
    expectTypeOf<'steVecTerm'>().toMatchTypeOf<QueryTypeName>()
  })

  it('EncryptedReturnType includes expected values', () => {
    expectTypeOf<'eql'>().toMatchTypeOf<EncryptedReturnType>()
    expectTypeOf<'composite-literal'>().toMatchTypeOf<EncryptedReturnType>()
    expectTypeOf<'escaped-composite-literal'>().toMatchTypeOf<EncryptedReturnType>()
  })

  it('InferPlaintext maps ProtectColumn keys to string', () => {
    const table = encryptedTable('users', {
      email: encryptedColumn('email'),
      name: encryptedColumn('name'),
    })
    type Plaintext = InferPlaintext<typeof table>
    expectTypeOf<Plaintext>().toMatchTypeOf<{ email: string; name: string }>()
  })

  it('InferEncrypted maps ProtectColumn keys to Encrypted', () => {
    const table = encryptedTable('users', {
      email: encryptedColumn('email'),
    })
    type Enc = InferEncrypted<typeof table>
    expectTypeOf<Enc>().toMatchTypeOf<{ email: Encrypted }>()
  })

  it('EncryptedFromSchema maps schema fields to Encrypted, leaves others unchanged', () => {
    type User = { id: string; email: string; createdAt: Date }
    type Schema = { email: EncryptedColumn }
    type Result = EncryptedFromSchema<User, Schema>
    expectTypeOf<Result>().toEqualTypeOf<{
      id: string
      email: Encrypted
      createdAt: Date
    }>()
  })

  it('EncryptedFromSchema with widened EncryptedTableColumn degrades to T', () => {
    type User = { id: string; email: string }
    type Result = EncryptedFromSchema<User, EncryptedTableColumn>
    // When S is the wide EncryptedTableColumn, S[K] is the full union, not EncryptedColumn alone.
    // The conditional [S[K]] extends [EncryptedColumn | EncryptedField] fails, so fields stay as-is.
    expectTypeOf<Result>().toEqualTypeOf<{ id: string; email: string }>()
  })

  it('Decrypted reverses EncryptedFromSchema correctly', () => {
    type User = { id: string; email: string; createdAt: Date }
    type Schema = { email: EncryptedColumn }
    type EncryptedUser = EncryptedFromSchema<User, Schema>
    type DecryptedUser = Decrypted<EncryptedUser>
    expectTypeOf<DecryptedUser>().toMatchTypeOf<{
      id: string
      email: string
      createdAt: Date
    }>()
  })

  it('encryptModel infers schema-aware return types from table argument', async () => {
    const users = encryptedTable('users', {
      name: encryptedColumn('name').equality(),
      email: encryptedColumn('email').freeTextSearch(),
    })

    const client = {} as EncryptionClient

    const result = await client.encryptModel(
      { name: 'John', email: 'john@example.com', age: 30 },
      users,
    )

    if (!result.failure) {
      // Schema fields should be Encrypted
      expectTypeOf(result.data.name).toEqualTypeOf<Encrypted>()
      expectTypeOf(result.data.email).toEqualTypeOf<Encrypted>()
      // Non-schema fields should keep their original type
      expectTypeOf(result.data.age).toEqualTypeOf<number>()
    }
  })
})
