import 'dotenv/config'
import type { ProtectClient } from '@cipherstash/protect'
import {
  csColumn,
  csTable,
  FfiProtectError,
  protect,
} from '@cipherstash/protect'
import { beforeAll, describe, expect, it } from 'vitest'
import { protectDynamoDB } from '../src'
import type { ProtectDynamoDBError } from '../src/types'

const FFI_TEST_TIMEOUT = 30_000

describe('ProtectDynamoDB Error Code Preservation', () => {
  let protectClient: ProtectClient
  let protectDynamo: ReturnType<typeof protectDynamoDB>

  const testSchema = csTable('test_table', {
    email: csColumn('email').equality(),
  })

  const badSchema = csTable('test_table', {
    nonexistent: csColumn('nonexistent_column'),
  })

  beforeAll(async () => {
    protectClient = await protect({ schemas: [testSchema] })
    protectDynamo = protectDynamoDB({ protectClient })
  })

  describe('handleError FFI error code extraction', () => {
    it('FfiProtectError has code property accessible', () => {
      const ffiError = new FfiProtectError({
        code: 'UNKNOWN_COLUMN',
        message: 'Test error',
      })
      expect(ffiError.code).toBe('UNKNOWN_COLUMN')
      expect(ffiError instanceof FfiProtectError).toBe(true)
    })
  })

  describe('encryptModel error codes', () => {
    it(
      'preserves FFI error codes',
      async () => {
        const model = { nonexistent: 'test value' }

        const result = await protectDynamo.encryptModel(model, badSchema)

        expect(result.failure).toBeDefined()
        expect((result.failure as ProtectDynamoDBError).code).toBe(
          'UNKNOWN_COLUMN',
        )
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('decryptModel error codes', () => {
    it(
      'uses PROTECT_DYNAMODB_ERROR for IO/parsing errors without FFI codes',
      async () => {
        // Malformed ciphertext causes IO/parsing errors that don't have FFI error codes
        const malformedItem = {
          email__source: 'invalid_ciphertext_data',
        }

        const result = await protectDynamo.decryptModel(
          malformedItem,
          testSchema,
        )

        expect(result.failure).toBeDefined()
        // FFI returns undefined code for IO/parsing errors, so we fall back to generic code
        expect((result.failure as ProtectDynamoDBError).code).toBe(
          'PROTECT_DYNAMODB_ERROR',
        )
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('bulkEncryptModels error codes', () => {
    it(
      'preserves FFI error codes',
      async () => {
        const models = [{ nonexistent: 'value1' }, { nonexistent: 'value2' }]

        const result = await protectDynamo.bulkEncryptModels(models, badSchema)

        expect(result.failure).toBeDefined()
        expect((result.failure as ProtectDynamoDBError).code).toBe(
          'UNKNOWN_COLUMN',
        )
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('bulkDecryptModels error codes', () => {
    it(
      'uses PROTECT_DYNAMODB_ERROR for IO/parsing errors without FFI codes',
      async () => {
        // Malformed ciphertext causes IO/parsing errors that don't have FFI error codes
        const malformedItems = [
          { email__source: 'invalid1' },
          { email__source: 'invalid2' },
        ]

        const result = await protectDynamo.bulkDecryptModels(
          malformedItems,
          testSchema,
        )

        expect(result.failure).toBeDefined()
        // FFI returns undefined code for IO/parsing errors, so we fall back to generic code
        expect((result.failure as ProtectDynamoDBError).code).toBe(
          'PROTECT_DYNAMODB_ERROR',
        )
      },
      FFI_TEST_TIMEOUT,
    )
  })
})
