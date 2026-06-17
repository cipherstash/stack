import 'dotenv/config'
import { ProtectError as FfiProtectError } from '@cipherstash/protect-ffi'
import { beforeAll, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { EncryptionErrorTypes } from '@/errors'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

/** FFI tests require longer timeout due to client initialization */
const FFI_TEST_TIMEOUT = 30_000

/**
 * Tests for FFI error code preservation in ProtectError.
 * These tests verify that specific FFI error codes are preserved when errors occur,
 * enabling programmatic error handling.
 */
describe('FFI Error Code Preservation', () => {
  let protectClient: EncryptionClient

  // Schema with a valid column for testing
  const testSchema = encryptedTable('test_table', {
    email: encryptedColumn('email').equality(),
    bio: encryptedColumn('bio').freeTextSearch(),
    age: encryptedColumn('age').dataType('number').orderAndRange(),
    metadata: encryptedColumn('metadata').searchableJson(),
  })

  // Schema without indexes for testing non-FFI validation
  const noIndexSchema = encryptedTable('no_index_table', {
    raw: encryptedColumn('raw'),
  })

  // Schema with non-existent column for triggering FFI UNKNOWN_COLUMN error
  const badModelSchema = encryptedTable('test_table', {
    nonexistent: encryptedColumn('nonexistent_column'),
  })

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [testSchema, noIndexSchema] })
  })

  describe('FfiProtectError class', () => {
    it('constructs with code and message', () => {
      const error = new FfiProtectError({
        code: 'UNKNOWN_COLUMN',
        message: 'Test error',
      })
      expect(error.code).toBe('UNKNOWN_COLUMN')
      expect(error.message).toBe('Test error')
    })
  })

  describe('encryptQuery error codes', () => {
    it(
      'returns UNKNOWN_COLUMN code for non-existent column',
      async () => {
        // Create a fake column that doesn't exist in the schema
        const fakeColumn = encryptedColumn('nonexistent_column').equality()

        const result = await protectClient.encryptQuery('test', {
          column: fakeColumn,
          table: testSchema,
          queryType: 'equality',
        })

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
      },
      FFI_TEST_TIMEOUT,
    )

    it(
      'returns undefined code for columns without indexes (non-FFI validation)',
      async () => {
        // This error is caught during pre-FFI validation, not by FFI itself
        const result = await protectClient.encryptQuery('test', {
          column: noIndexSchema.raw,
          table: noIndexSchema,
        })

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.message).toContain('no indexes configured')
        // Pre-FFI validation errors don't have FFI error codes
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )

    it(
      'returns undefined code for non-FFI validation errors',
      async () => {
        // NaN validation happens before FFI call
        const result = await protectClient.encryptQuery(Number.NaN, {
          column: testSchema.age,
          table: testSchema,
          queryType: 'orderAndRange',
        })

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        // Non-FFI errors should have undefined code
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('batch encryptQuery error codes', () => {
    it(
      'preserves error code in batch operations',
      async () => {
        const fakeColumn = encryptedColumn('nonexistent_column').equality()

        const result = await protectClient.encryptQuery([
          {
            value: 'test',
            column: fakeColumn,
            table: testSchema,
            queryType: 'equality',
          },
        ])

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
      },
      FFI_TEST_TIMEOUT,
    )

    it(
      'returns undefined code for non-FFI batch errors',
      async () => {
        const result = await protectClient.encryptQuery([
          {
            value: Number.NaN,
            column: testSchema.age,
            table: testSchema,
            queryType: 'orderAndRange',
          },
        ])

        expect(result.failure).toBeDefined()
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('encrypt error codes', () => {
    it(
      'returns UNKNOWN_COLUMN code for non-existent column in encrypt',
      async () => {
        const fakeColumn = encryptedColumn('nonexistent_column')

        const result = await protectClient.encrypt('test', {
          column: fakeColumn,
          table: testSchema,
        })

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
      },
      FFI_TEST_TIMEOUT,
    )

    it(
      'returns undefined code for non-FFI encrypt errors',
      async () => {
        const result = await protectClient.encrypt(Number.NaN, {
          column: testSchema.age,
          table: testSchema,
        })

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        // NaN validation happens before FFI call
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('decrypt error codes', () => {
    it(
      'returns undefined code for malformed ciphertext (non-FFI validation)',
      async () => {
        // This error occurs during ciphertext parsing, not FFI decryption
        const invalidCiphertext = {
          i: { t: 'test_table', c: 'nonexistent' },
          v: 2,
          c: 'invalid_ciphertext_data',
        }

        const result = await protectClient.decrypt(invalidCiphertext)

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.DecryptionError)
        // Malformed ciphertext errors are caught before FFI and don't have codes
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('bulkEncrypt error codes', () => {
    it(
      'returns UNKNOWN_COLUMN code for non-existent column',
      async () => {
        const fakeColumn = encryptedColumn('nonexistent_column')

        const result = await protectClient.bulkEncrypt(
          [{ plaintext: 'test1' }, { plaintext: 'test2' }],
          {
            column: fakeColumn,
            table: testSchema,
          },
        )

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
      },
      FFI_TEST_TIMEOUT,
    )

    it(
      'returns undefined code for non-FFI validation errors',
      async () => {
        const result = await protectClient.bulkEncrypt(
          [{ plaintext: Number.NaN }],
          {
            column: testSchema.age,
            table: testSchema,
          },
        )

        expect(result.failure).toBeDefined()
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('bulkDecrypt error codes', () => {
    it(
      'returns undefined code for malformed ciphertexts (non-FFI validation)',
      async () => {
        // bulkDecrypt uses the "fallible" FFI API (decryptBulkFallible) which normally:
        // - Succeeds at the operation level
        // - Returns per-item results with either { data } or { error }
        //
        // However, malformed ciphertexts cause parsing errors BEFORE the fallible API,
        // which throws and triggers a top-level failure (not per-item errors).
        // These pre-FFI errors don't have structured FFI error codes.
        const invalidCiphertexts = [
          { data: { i: { t: 'test_table', c: 'email' }, v: 2, c: 'invalid1' } },
          { data: { i: { t: 'test_table', c: 'email' }, v: 2, c: 'invalid2' } },
        ]

        const result = await protectClient.bulkDecrypt(invalidCiphertexts)

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.DecryptionError)
        // FFI parsing errors don't have structured error codes
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('encryptModel error codes', () => {
    it(
      'returns UNKNOWN_COLUMN code for model with non-existent column',
      async () => {
        const model = { nonexistent: 'test value' }

        const result = await protectClient.encryptModel(model, badModelSchema)

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('decryptModel error codes', () => {
    it(
      'returns undefined code for malformed model (non-FFI validation)',
      async () => {
        const malformedModel = {
          email: {
            i: { t: 'test_table', c: 'email' },
            v: 2,
            c: 'invalid_ciphertext',
          },
        }

        const result = await protectClient.decryptModel(malformedModel)

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.DecryptionError)
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('bulkEncryptModels error codes', () => {
    it(
      'returns UNKNOWN_COLUMN code for models with non-existent column',
      async () => {
        const models = [{ nonexistent: 'value1' }, { nonexistent: 'value2' }]

        const result = await protectClient.bulkEncryptModels(
          models,
          badModelSchema,
        )

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.EncryptionError)
        expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
      },
      FFI_TEST_TIMEOUT,
    )
  })

  describe('bulkDecryptModels error codes', () => {
    it(
      'returns undefined code for malformed models (non-FFI validation)',
      async () => {
        const malformedModels = [
          {
            email: { i: { t: 'test_table', c: 'email' }, v: 2, c: 'invalid1' },
          },
          {
            email: { i: { t: 'test_table', c: 'email' }, v: 2, c: 'invalid2' },
          },
        ]

        const result = await protectClient.bulkDecryptModels(malformedModels)

        expect(result.failure).toBeDefined()
        expect(result.failure?.type).toBe(EncryptionErrorTypes.DecryptionError)
        expect(result.failure?.code).toBeUndefined()
      },
      FFI_TEST_TIMEOUT,
    )
  })
})
