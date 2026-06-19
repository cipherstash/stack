import 'dotenv/config'
import { describe, expect, it, vi } from 'vitest'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedField, encryptedTable } from '@/schema'

const users = encryptedTable('users', {
  email: encryptedColumn('email').freeTextSearch().equality().orderAndRange(),
  address: encryptedColumn('address').freeTextSearch(),
  name: encryptedColumn('name').freeTextSearch(),
  example: {
    field: encryptedField('example.field'),
    nested: {
      deeper: encryptedField('example.nested.deeper'),
    },
  },
})

type User = {
  id: string
  email?: string | null
  createdAt?: Date
  updatedAt?: Date
  address?: string | null
  notEncrypted?: string | null
  example: {
    field: string | undefined | null
    nested?: {
      deeper: string | undefined | null
      plaintext?: string | undefined | null
      notInSchema?: {
        deeper: string | undefined | null
      }
      deeperNotInSchema?: string | undefined | null
      extra?: {
        plaintext: string | undefined | null
      }
    }
    plaintext?: string | undefined | null
    fieldNotInSchema?: string | undefined | null
    notInSchema?: {
      deeper: string | undefined | null
    }
  }
}

describe('encrypt models with nested fields', () => {
  it('should encrypt and decrypt a single value from a nested schema', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const encryptResponse = await protectClient.encrypt('hello world', {
      column: users.example.field,
      table: users,
    })

    if (encryptResponse.failure) {
      throw new Error(`[protect]: ${encryptResponse.failure.message}`)
    }

    // Verify encrypted field
    expect(encryptResponse.data).toHaveProperty('c')

    const decryptResponse = await protectClient.decrypt(encryptResponse.data)

    if (decryptResponse.failure) {
      throw new Error(`[protect]: ${decryptResponse.failure.message}`)
    }

    expect(decryptResponse).toEqual({
      data: 'hello world',
    })
  })

  it('should encrypt and decrypt a model with nested fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      address: '123 Main St',
      notEncrypted: 'not encrypted',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      example: {
        field: 'test',
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.example.field).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.notEncrypted).toBe('not encrypted')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle null values in nested fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '2',
      email: null,
      address: null,
      example: {
        field: null,
        nested: {
          deeper: null,
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify null fields are preserved
    expect(encryptedModel.data.email).toBeNull()
    expect(encryptedModel.data.address).toBeNull()
    expect(encryptedModel.data.example.field).toBeNull()
    expect(encryptedModel.data.example.nested?.deeper).toBeNull()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle undefined values in nested fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '3',
      example: {
        field: undefined,
        nested: {
          deeper: undefined,
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify undefined fields are preserved
    expect(encryptedModel.data.email).toBeUndefined()
    expect(encryptedModel.data.example.field).toBeUndefined()
    expect(encryptedModel.data.example.nested?.deeper).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle mixed null and undefined values in nested fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '4',
      email: 'test@example.com',
      address: undefined,
      notEncrypted: 'not encrypted',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      example: {
        field: null,
        nested: {
          deeper: undefined,
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')

    // Verify null/undefined fields are preserved
    expect(encryptedModel.data.address).toBeUndefined()
    expect(encryptedModel.data.example.field).toBeNull()
    expect(encryptedModel.data.example.nested?.deeper).toBeUndefined()

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('4')
    expect(encryptedModel.data.notEncrypted).toBe('not encrypted')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle deeply nested fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '3',
      example: {
        field: 'outer',
        nested: {
          deeper: 'inner value',
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.example.field).toHaveProperty('c')
    expect(encryptedModel.data.example.nested?.deeper).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('3')

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle missing optional nested fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '5',
      example: {
        field: 'present',
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.example.field).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('5')
    expect(encryptedModel.data.example.nested).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  describe('bulk operations with nested fields', () => {
    it('should handle bulk encryption and decryption of models with nested fields', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = [
        {
          id: '1',
          email: 'test1@example.com',
          example: {
            field: 'test1',
            nested: {
              deeper: 'value1',
            },
          },
        },
        {
          id: '2',
          email: 'test2@example.com',
          example: {
            field: 'test2',
            nested: {
              deeper: 'value2',
            },
          },
        },
      ]

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      // Verify encrypted fields for each model
      expect(encryptedModels.data[0].email).toHaveProperty('c')
      expect(encryptedModels.data[0].example.field).toHaveProperty('c')
      expect(encryptedModels.data[0].example.nested?.deeper).toHaveProperty('c')
      expect(encryptedModels.data[1].email).toHaveProperty('c')
      expect(encryptedModels.data[1].example.field).toHaveProperty('c')
      expect(encryptedModels.data[1].example.nested?.deeper).toHaveProperty('c')

      // Verify non-encrypted fields remain unchanged
      expect(encryptedModels.data[0].id).toBe('1')
      expect(encryptedModels.data[1].id).toBe('2')

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual(decryptedModels)
    }, 30000)

    it('should handle bulk operations with null and undefined values in nested fields', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = [
        {
          id: '1',
          email: null,
          example: {
            field: null,
            nested: {
              deeper: undefined,
            },
          },
        },
        {
          id: '2',
          email: undefined,
          example: {
            field: undefined,
            nested: {
              deeper: null,
            },
          },
        },
      ]

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      // Verify null/undefined fields are preserved
      expect(encryptedModels.data[0].email).toBeNull()
      expect(encryptedModels.data[0].example.field).toBeNull()
      expect(encryptedModels.data[0].example.nested?.deeper).toBeUndefined()
      expect(encryptedModels.data[1].email).toBeUndefined()
      expect(encryptedModels.data[1].example.field).toBeUndefined()
      expect(encryptedModels.data[1].example.nested?.deeper).toBeNull()

      // Verify non-encrypted fields remain unchanged
      expect(encryptedModels.data[0].id).toBe('1')
      expect(encryptedModels.data[1].id).toBe('2')

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual(decryptedModels)
    }, 30000)

    it('should handle bulk operations with missing optional nested fields', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = [
        {
          id: '1',
          email: 'test1@example.com',
          example: {
            field: 'test1',
          },
        },
        {
          id: '2',
          email: 'test2@example.com',
          example: {
            field: 'test2',
            nested: {
              deeper: 'value2',
            },
          },
        },
      ]

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      // Verify encrypted fields for each model
      expect(encryptedModels.data[0].email).toHaveProperty('c')
      expect(encryptedModels.data[0].example.field).toHaveProperty('c')
      expect(encryptedModels.data[1].email).toHaveProperty('c')
      expect(encryptedModels.data[1].example.field).toHaveProperty('c')
      expect(encryptedModels.data[1].example.nested?.deeper).toHaveProperty('c')

      // Verify non-encrypted fields remain unchanged
      expect(encryptedModels.data[0].id).toBe('1')
      expect(encryptedModels.data[0].example.nested).toBeUndefined()
      expect(encryptedModels.data[1].id).toBe('2')

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual(decryptedModels)
    }, 30000)

    it('should handle empty array in bulk operations', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = []

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      expect(encryptedModels.data).toEqual([])

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual([])
    }, 30000)
  })
})

describe('nested fields with a plaintext field', () => {
  it('should handle nested fields with a plaintext field', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      address: '123 Main St',
      notEncrypted: 'not encrypted',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      example: {
        field: 'test',
        plaintext: 'plaintext',
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.example.field).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.notEncrypted).toBe('not encrypted')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.example.plaintext).toBe('plaintext')

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  })

  it('should handle multiple plaintext fields at different nesting levels', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      address: '123 Main St',
      notEncrypted: 'not encrypted',
      example: {
        field: 'encrypted field',
        plaintext: 'top level plaintext',
        nested: {
          deeper: 'encrypted deeper',
          plaintext: 'nested plaintext',
          extra: {
            plaintext: 'deeply nested plaintext',
          },
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.example.field).toHaveProperty('c')
    expect(encryptedModel.data.example.nested?.deeper).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.notEncrypted).toBe('not encrypted')
    expect(encryptedModel.data.example.plaintext).toBe('top level plaintext')
    expect(encryptedModel.data.example.nested?.plaintext).toBe(
      'nested plaintext',
    )
    expect(encryptedModel.data.example.nested?.extra?.plaintext).toBe(
      'deeply nested plaintext',
    )

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  })

  it('should handle partial path matches in nested objects', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      example: {
        field: 'encrypted field',
        nested: {
          deeper: 'encrypted deeper',
          // This should not be encrypted as it's not in the schema
          notInSchema: {
            deeper: 'not encrypted',
          },
        },
        // This should not be encrypted as it's not in the schema
        notInSchema: {
          deeper: 'not encrypted',
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.example.field).toHaveProperty('c')
    expect(encryptedModel.data.example.nested?.deeper).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.example.nested?.notInSchema?.deeper).toBe(
      'not encrypted',
    )
    expect(encryptedModel.data.example.notInSchema?.deeper).toBe(
      'not encrypted',
    )

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  })

  it('should handle mixed encrypted and plaintext fields with similar paths', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      example: {
        field: 'encrypted field',
        fieldNotInSchema: 'not encrypted',
        nested: {
          deeper: 'encrypted deeper',
          deeperNotInSchema: 'not encrypted',
        },
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.example.field).toHaveProperty('c')
    expect(encryptedModel.data.example.nested?.deeper).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.example.fieldNotInSchema).toBe('not encrypted')
    expect(encryptedModel.data.example.nested?.deeperNotInSchema).toBe(
      'not encrypted',
    )

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  })

  describe('bulk operations with plaintext fields', () => {
    it('should handle bulk encryption and decryption with plaintext fields', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = [
        {
          id: '1',
          email: 'test1@example.com',
          address: '123 Main St',
          example: {
            field: 'encrypted field 1',
            plaintext: 'plaintext 1',
            nested: {
              deeper: 'encrypted deeper 1',
              plaintext: 'nested plaintext 1',
            },
          },
        },
        {
          id: '2',
          email: 'test2@example.com',
          address: '456 Main St',
          example: {
            field: 'encrypted field 2',
            plaintext: 'plaintext 2',
            nested: {
              deeper: 'encrypted deeper 2',
              plaintext: 'nested plaintext 2',
            },
          },
        },
      ]

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      // Verify encrypted fields
      expect(encryptedModels.data[0].email).toHaveProperty('c')
      expect(encryptedModels.data[0].address).toHaveProperty('c')
      expect(encryptedModels.data[0].example.field).toHaveProperty('c')
      expect(encryptedModels.data[0].example.nested?.deeper).toHaveProperty('c')
      expect(encryptedModels.data[1].email).toHaveProperty('c')
      expect(encryptedModels.data[1].address).toHaveProperty('c')
      expect(encryptedModels.data[1].example.field).toHaveProperty('c')
      expect(encryptedModels.data[1].example.nested?.deeper).toHaveProperty('c')

      // Verify non-encrypted fields remain unchanged
      expect(encryptedModels.data[0].id).toBe('1')
      expect(encryptedModels.data[0].example.plaintext).toBe('plaintext 1')
      expect(encryptedModels.data[0].example.nested?.plaintext).toBe(
        'nested plaintext 1',
      )
      expect(encryptedModels.data[1].id).toBe('2')
      expect(encryptedModels.data[1].example.plaintext).toBe('plaintext 2')
      expect(encryptedModels.data[1].example.nested?.plaintext).toBe(
        'nested plaintext 2',
      )

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual(decryptedModels)
    })

    it('should handle bulk operations with mixed encrypted and non-encrypted fields', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = [
        {
          id: '1',
          email: 'test1@example.com',
          example: {
            field: 'encrypted field 1',
            fieldNotInSchema: 'not encrypted 1',
            nested: {
              deeper: 'encrypted deeper 1',
              deeperNotInSchema: 'not encrypted deeper 1',
            },
          },
        },
        {
          id: '2',
          email: 'test2@example.com',
          example: {
            field: 'encrypted field 2',
            fieldNotInSchema: 'not encrypted 2',
            nested: {
              deeper: 'encrypted deeper 2',
              deeperNotInSchema: 'not encrypted deeper 2',
            },
          },
        },
      ]

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      // Verify encrypted fields
      expect(encryptedModels.data[0].email).toHaveProperty('c')
      expect(encryptedModels.data[0].example.field).toHaveProperty('c')
      expect(encryptedModels.data[0].example.nested?.deeper).toHaveProperty('c')
      expect(encryptedModels.data[1].email).toHaveProperty('c')
      expect(encryptedModels.data[1].example.field).toHaveProperty('c')
      expect(encryptedModels.data[1].example.nested?.deeper).toHaveProperty('c')

      // Verify non-encrypted fields remain unchanged
      expect(encryptedModels.data[0].id).toBe('1')
      expect(encryptedModels.data[0].example.fieldNotInSchema).toBe(
        'not encrypted 1',
      )
      expect(encryptedModels.data[0].example.nested?.deeperNotInSchema).toBe(
        'not encrypted deeper 1',
      )
      expect(encryptedModels.data[1].id).toBe('2')
      expect(encryptedModels.data[1].example.fieldNotInSchema).toBe(
        'not encrypted 2',
      )
      expect(encryptedModels.data[1].example.nested?.deeperNotInSchema).toBe(
        'not encrypted deeper 2',
      )

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual(decryptedModels)
    })

    it('should handle bulk operations with deeply nested plaintext fields', async () => {
      const protectClient = await Encryption({ schemas: [users] })

      const decryptedModels: User[] = [
        {
          id: '1',
          email: 'test1@example.com',
          example: {
            field: 'encrypted field 1',
            nested: {
              deeper: 'encrypted deeper 1',
              extra: {
                plaintext: 'deeply nested plaintext 1',
              },
            },
          },
        },
        {
          id: '2',
          email: 'test2@example.com',
          example: {
            field: 'encrypted field 2',
            nested: {
              deeper: 'encrypted deeper 2',
              extra: {
                plaintext: 'deeply nested plaintext 2',
              },
            },
          },
        },
      ]

      const encryptedModels = await protectClient.bulkEncryptModels<User>(
        decryptedModels,
        users,
      )

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      // Verify encrypted fields
      expect(encryptedModels.data[0].email).toHaveProperty('c')
      expect(encryptedModels.data[0].example.field).toHaveProperty('c')
      expect(encryptedModels.data[0].example.nested?.deeper).toHaveProperty('c')
      expect(encryptedModels.data[1].email).toHaveProperty('c')
      expect(encryptedModels.data[1].example.field).toHaveProperty('c')
      expect(encryptedModels.data[1].example.nested?.deeper).toHaveProperty('c')

      // Verify non-encrypted fields remain unchanged
      expect(encryptedModels.data[0].id).toBe('1')
      expect(encryptedModels.data[0].example.nested?.extra?.plaintext).toBe(
        'deeply nested plaintext 1',
      )
      expect(encryptedModels.data[1].id).toBe('2')
      expect(encryptedModels.data[1].example.nested?.extra?.plaintext).toBe(
        'deeply nested plaintext 2',
      )

      const decryptedResults = await protectClient.bulkDecryptModels<User>(
        encryptedModels.data,
      )

      if (decryptedResults.failure) {
        throw new Error(`[protect]: ${decryptedResults.failure.message}`)
      }

      expect(decryptedResults.data).toEqual(decryptedModels)
    })
  })
})
