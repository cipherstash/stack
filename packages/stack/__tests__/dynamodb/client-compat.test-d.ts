import { describe, expectTypeOf, it } from 'vitest'
import { type EncryptedDynamoDBInstance, encryptedDynamoDB } from '@/dynamodb'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  age: types.IntegerOrd('age'),
})

declare const client: EncryptionClient<readonly [typeof users]>
const dynamo = encryptedDynamoDB({ encryptionClient: client })

describe('v3-only DynamoDB types', () => {
  it('accepts the generic Encryption client', () => {
    expectTypeOf(dynamo).toEqualTypeOf<EncryptedDynamoDBInstance>()
  })

  it('allows storedEqlVersion only on reads', () => {
    dynamo.decryptModel({ email__source: 'ciphertext' }, users, {
      storedEqlVersion: 2,
    })
    dynamo.bulkDecryptModels([{ email__source: 'ciphertext' }], users, {
      storedEqlVersion: 2,
    })

    // @ts-expect-error - the legacy wire hint is read-only
    dynamo.encryptModel({ email: 'a@b.com' }, users, {
      storedEqlVersion: 2,
    })
  })

  it('rejects invalid stored versions', () => {
    dynamo.decryptModel({ email__source: 'ciphertext' }, users, {
      // @ts-expect-error - only EQL v2 and v3 exist
      storedEqlVersion: 4,
    })
  })
})
