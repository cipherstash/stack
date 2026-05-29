import {
  type Encrypted as CipherStashEncrypted,
  decryptBulk,
  encryptBulk,
} from '@cipherstash/protect-ffi'
import { isEncryptedPayload } from '@/encryption/helpers'
import type { AuditData } from '@/encryption/operations/base-operation'
import type { GetLockContextResponse } from '@/identity'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { Client, Decrypted, Encrypted } from '@/types'

/**
 * Sets a value at a nested path in an object, creating intermediate objects as needed.
 * Includes prototype pollution protection.
 */
function setNestedValue(
  obj: Record<string, unknown>,
  path: string[],
  value: unknown,
): void {
  const FORBIDDEN_KEYS = ['__proto__', 'prototype', 'constructor']
  let current: Record<string, unknown> = obj
  for (let i = 0; i < path.length - 1; i++) {
    const part = path[i]
    if (FORBIDDEN_KEYS.includes(part)) {
      throw new Error(`[encryption]: Forbidden key "${part}" in field path`)
    }
    if (
      !(part in current) ||
      typeof current[part] !== 'object' ||
      current[part] === null
    ) {
      current[part] = {}
    }
    current = current[part] as Record<string, unknown>
  }
  const lastKey = path[path.length - 1]
  if (FORBIDDEN_KEYS.includes(lastKey)) {
    throw new Error(`[encryption]: Forbidden key "${lastKey}" in field path`)
  }
  current[lastKey] = value
}

/**
 * Helper function to extract encrypted fields from a model
 */
export function extractEncryptedFields<T extends Record<string, unknown>>(
  model: T,
): Record<string, Encrypted> {
  const result: Record<string, Encrypted> = {}

  for (const [key, value] of Object.entries(model)) {
    if (isEncryptedPayload(value)) {
      result[key] = value
    }
  }

  return result
}

/**
 * Helper function to extract non-encrypted fields from a model
 */
export function extractOtherFields<T extends Record<string, unknown>>(
  model: T,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(model)) {
    if (!isEncryptedPayload(value)) {
      result[key] = value
    }
  }

  return result
}

/**
 * Helper function to merge encrypted and non-encrypted fields into a model
 */
export function mergeFields<T>(
  otherFields: Record<string, unknown>,
  encryptedFields: Record<string, Encrypted>,
): T {
  return { ...otherFields, ...encryptedFields } as T
}

/**
 * Base interface for bulk operation payloads
 */
interface BulkOperationPayload {
  id: string
  [key: string]: unknown
}

/**
 * Interface for bulk operation key mapping
 */
interface BulkOperationKeyMap {
  modelIndex: number
  fieldKey: string
}

/**
 * Helper function to handle single model bulk operations with mapping
 */
async function handleSingleModelBulkOperation<
  T extends BulkOperationPayload,
  R,
>(
  items: T[],
  operation: (items: T[]) => Promise<R[]>,
  keyMap: Record<string, string>,
): Promise<Record<string, R>> {
  if (items.length === 0) {
    return {}
  }

  const results = await operation(items)
  const mappedResults: Record<string, R> = {}

  results.forEach((result, index) => {
    const originalKey = keyMap[index.toString()]
    mappedResults[originalKey] = result
  })

  return mappedResults
}

/**
 * Helper function to handle multiple model bulk operations with mapping
 */
async function handleMultiModelBulkOperation<T extends BulkOperationPayload, R>(
  items: T[],
  operation: (items: T[]) => Promise<R[]>,
  keyMap: Record<string, BulkOperationKeyMap>,
): Promise<Record<string, R>> {
  if (items.length === 0) {
    return {}
  }

  const results = await operation(items)
  const mappedResults: Record<string, R> = {}

  results.forEach((result, index) => {
    const key = index.toString()
    const { modelIndex, fieldKey } = keyMap[key]
    mappedResults[`${modelIndex}-${fieldKey}`] = result
  })

  return mappedResults
}

/**
 * Helper function to prepare fields for decryption
 */
function prepareFieldsForDecryption<T extends Record<string, unknown>>(
  model: T,
): {
  otherFields: Record<string, unknown>
  operationFields: Record<string, unknown>
  keyMap: Record<string, string>
  nullFields: Record<string, null | undefined>
} {
  const otherFields = { ...model } as Record<string, unknown>
  const operationFields: Record<string, unknown> = {}
  const nullFields: Record<string, null | undefined> = {}
  const keyMap: Record<string, string> = {}
  let index = 0

  const processNestedFields = (obj: Record<string, unknown>, prefix = '') => {
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key

      if (value === null || value === undefined) {
        nullFields[fullKey] = value
        continue
      }

      if (typeof value === 'object' && !isEncryptedPayload(value)) {
        // Recursively process nested objects
        processNestedFields(value as Record<string, unknown>, fullKey)
      } else if (isEncryptedPayload(value)) {
        // This is an encrypted field
        const id = index.toString()
        keyMap[id] = fullKey
        operationFields[fullKey] = value
        index++

        // Remove from otherFields
        const parts = fullKey.split('.')
        let current = otherFields
        for (let i = 0; i < parts.length - 1; i++) {
          current = current[parts[i]] as Record<string, unknown>
        }
        delete current[parts[parts.length - 1]]
      }
    }
  }

  processNestedFields(model)
  return { otherFields, operationFields, keyMap, nullFields }
}

/**
 * Helper function to prepare fields for encryption
 */
function prepareFieldsForEncryption<T extends Record<string, unknown>>(
  model: T,
  table: EncryptedTable<EncryptedTableColumn>,
): {
  otherFields: Record<string, unknown>
  operationFields: Record<string, unknown>
  keyMap: Record<string, string>
  nullFields: Record<string, null | undefined>
} {
  const otherFields = { ...model } as Record<string, unknown>
  const operationFields: Record<string, unknown> = {}
  const nullFields: Record<string, null | undefined> = {}
  const keyMap: Record<string, string> = {}
  let index = 0

  const processNestedFields = (
    obj: Record<string, unknown>,
    prefix = '',
    columnPaths: string[] = [],
  ) => {
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key

      if (value === null || value === undefined) {
        nullFields[fullKey] = value
        continue
      }

      if (
        typeof value === 'object' &&
        !isEncryptedPayload(value) &&
        !columnPaths.includes(fullKey)
      ) {
        // Only process nested objects if they're in the schema
        if (columnPaths.some((path) => path.startsWith(fullKey))) {
          processNestedFields(
            value as Record<string, unknown>,
            fullKey,
            columnPaths,
          )
        }
      } else if (columnPaths.includes(fullKey)) {
        // Only process fields that are explicitly defined in the schema
        const id = index.toString()
        keyMap[id] = fullKey
        operationFields[fullKey] = value
        index++

        // Remove from otherFields
        const parts = fullKey.split('.')
        let current = otherFields
        for (let i = 0; i < parts.length - 1; i++) {
          current = current[parts[i]] as Record<string, unknown>
        }
        delete current[parts[parts.length - 1]]
      }
    }
  }

  // Get all column paths from the table schema
  const columnPaths = Object.keys(table.build().columns)
  processNestedFields(model, '', columnPaths)

  return { otherFields, operationFields, keyMap, nullFields }
}

/**
 * Helper function to convert a model with encrypted fields to a decrypted model
 */
export async function decryptModelFields<T extends Record<string, unknown>>(
  model: T,
  client: Client,
  auditData?: AuditData,
): Promise<Decrypted<T>> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareFieldsForDecryption(model)

  const bulkDecryptPayload = Object.entries(operationFields).map(
    ([key, value]) => ({
      id: key,
      ciphertext: value as CipherStashEncrypted,
    }),
  )

  const decryptedFields = await handleSingleModelBulkOperation(
    bulkDecryptPayload,
    (items) =>
      decryptBulk(client, {
        ciphertexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  // Reconstruct the object with proper nesting
  const result: Record<string, unknown> = { ...otherFields }

  // First, reconstruct the null/undefined fields
  for (const [key, value] of Object.entries(nullFields)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  // Then, reconstruct the decrypted fields
  for (const [key, value] of Object.entries(decryptedFields)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  return result as Decrypted<T>
}

/**
 * Helper function to convert a decrypted model to a model with encrypted fields
 */
export async function encryptModelFields(
  model: Record<string, unknown>,
  table: EncryptedTable<EncryptedTableColumn>,
  client: Client,
  auditData?: AuditData,
): Promise<Record<string, unknown>> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareFieldsForEncryption(model, table)

  const bulkEncryptPayload = Object.entries(operationFields).map(
    ([key, value]) => ({
      id: key,
      plaintext: value as string,
      table: table.tableName,
      column: key,
    }),
  )

  const encryptedData = await handleSingleModelBulkOperation(
    bulkEncryptPayload,
    (items) =>
      encryptBulk(client, {
        plaintexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  // Reconstruct the object with proper nesting
  const result: Record<string, unknown> = { ...otherFields }

  // First, reconstruct the null/undefined fields
  for (const [key, value] of Object.entries(nullFields)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  // Then, reconstruct the encrypted fields
  for (const [key, value] of Object.entries(encryptedData)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  return result
}

/**
 * Helper function to convert a model with encrypted fields to a decrypted model with lock context
 */
export async function decryptModelFieldsWithLockContext<
  T extends Record<string, unknown>,
>(
  model: T,
  client: Client,
  lockContext: GetLockContextResponse,
  auditData?: AuditData,
): Promise<Decrypted<T>> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  if (!lockContext) {
    throw new Error('Lock context is not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareFieldsForDecryption(model)

  const bulkDecryptPayload = Object.entries(operationFields).map(
    ([key, value]) => ({
      id: key,
      ciphertext: value as CipherStashEncrypted,
      lockContext: lockContext.context,
    }),
  )

  const decryptedFields = await handleSingleModelBulkOperation(
    bulkDecryptPayload,
    (items) =>
      decryptBulk(client, {
        ciphertexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  // Reconstruct the object with proper nesting
  const result: Record<string, unknown> = { ...otherFields }

  // First, reconstruct the null/undefined fields
  for (const [key, value] of Object.entries(nullFields)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  // Then, reconstruct the decrypted fields
  for (const [key, value] of Object.entries(decryptedFields)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  return result as Decrypted<T>
}

/**
 * Helper function to convert a decrypted model to a model with encrypted fields with lock context
 */
export async function encryptModelFieldsWithLockContext(
  model: Record<string, unknown>,
  table: EncryptedTable<EncryptedTableColumn>,
  client: Client,
  lockContext: GetLockContextResponse,
  auditData?: AuditData,
): Promise<Record<string, unknown>> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  if (!lockContext) {
    throw new Error('Lock context is not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareFieldsForEncryption(model, table)

  const bulkEncryptPayload = Object.entries(operationFields).map(
    ([key, value]) => ({
      id: key,
      plaintext: value as string,
      table: table.tableName,
      column: key,
      lockContext: lockContext.context,
    }),
  )

  const encryptedData = await handleSingleModelBulkOperation(
    bulkEncryptPayload,
    (items) =>
      encryptBulk(client, {
        plaintexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  // Reconstruct the object with proper nesting
  const result: Record<string, unknown> = { ...otherFields }

  // First, reconstruct the null/undefined fields
  for (const [key, value] of Object.entries(nullFields)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  // Then, reconstruct the encrypted fields
  for (const [key, value] of Object.entries(encryptedData)) {
    const parts = key.split('.')
    setNestedValue(result, parts, value)
  }

  return result
}

/**
 * Helper function to prepare multiple models for bulk operation
 */
function prepareBulkModelsForOperation<T extends Record<string, unknown>>(
  models: T[],
  table?: EncryptedTable<EncryptedTableColumn>,
): {
  otherFields: Record<string, unknown>[]
  operationFields: Record<string, unknown>[]
  keyMap: Record<string, { modelIndex: number; fieldKey: string }>
  nullFields: Record<string, null | undefined>[]
} {
  const otherFields: Record<string, unknown>[] = []
  const operationFields: Record<string, unknown>[] = []
  const nullFields: Record<string, null | undefined>[] = []
  const keyMap: Record<string, { modelIndex: number; fieldKey: string }> = {}
  let index = 0

  for (let modelIndex = 0; modelIndex < models.length; modelIndex++) {
    const model = models[modelIndex]
    const modelOtherFields = { ...model } as Record<string, unknown>
    const modelOperationFields: Record<string, unknown> = {}
    const modelNullFields: Record<string, null | undefined> = {}

    const processNestedFields = (
      obj: Record<string, unknown>,
      prefix = '',
      columnPaths: string[] = [],
    ) => {
      for (const [key, value] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${key}` : key

        if (value === null || value === undefined) {
          modelNullFields[fullKey] = value
          continue
        }

        if (
          typeof value === 'object' &&
          !isEncryptedPayload(value) &&
          !columnPaths.includes(fullKey)
        ) {
          // Only process nested objects if they're in the schema
          if (columnPaths.some((path) => path.startsWith(fullKey))) {
            processNestedFields(
              value as Record<string, unknown>,
              fullKey,
              columnPaths,
            )
          }
        } else if (columnPaths.includes(fullKey)) {
          // Only process fields that are explicitly defined in the schema
          const id = index.toString()
          keyMap[id] = { modelIndex, fieldKey: fullKey }
          modelOperationFields[fullKey] = value
          index++

          // Remove from otherFields
          const parts = fullKey.split('.')
          let current = modelOtherFields
          for (let i = 0; i < parts.length - 1; i++) {
            current = current[parts[i]] as Record<string, unknown>
          }
          delete current[parts[parts.length - 1]]
        }
      }
    }

    if (table) {
      // Get all column paths from the table schema
      const columnPaths = Object.keys(table.build().columns)
      processNestedFields(model, '', columnPaths)
    } else {
      // For decryption, process all encrypted fields
      const processEncryptedFields = (
        obj: Record<string, unknown>,
        prefix = '',
        columnPaths: string[] = [],
      ) => {
        for (const [key, value] of Object.entries(obj)) {
          const fullKey = prefix ? `${prefix}.${key}` : key

          if (value === null || value === undefined) {
            modelNullFields[fullKey] = value
            continue
          }

          if (
            typeof value === 'object' &&
            !isEncryptedPayload(value) &&
            !columnPaths.includes(fullKey)
          ) {
            // Recursively process nested objects
            processEncryptedFields(
              value as Record<string, unknown>,
              fullKey,
              columnPaths,
            )
          } else if (isEncryptedPayload(value)) {
            // This is an encrypted field
            const id = index.toString()
            keyMap[id] = { modelIndex, fieldKey: fullKey }
            modelOperationFields[fullKey] = value
            index++

            // Remove from otherFields
            const parts = fullKey.split('.')
            let current = modelOtherFields
            for (let i = 0; i < parts.length - 1; i++) {
              current = current[parts[i]] as Record<string, unknown>
            }
            delete current[parts[parts.length - 1]]
          }
        }
      }
      processEncryptedFields(model)
    }

    otherFields.push(modelOtherFields)
    operationFields.push(modelOperationFields)
    nullFields.push(modelNullFields)
  }

  return { otherFields, operationFields, keyMap, nullFields }
}

/**
 * Helper function to convert multiple decrypted models to models with encrypted fields
 */
export async function bulkEncryptModels(
  models: Record<string, unknown>[],
  table: EncryptedTable<EncryptedTableColumn>,
  client: Client,
  auditData?: AuditData,
): Promise<Record<string, unknown>[]> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  if (!models || models.length === 0) {
    return []
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareBulkModelsForOperation(models, table)

  const bulkEncryptPayload = operationFields.flatMap((fields, modelIndex) =>
    Object.entries(fields).map(([key, value]) => ({
      id: `${modelIndex}-${key}`,
      plaintext: value as string,
      table: table.tableName,
      column: key,
    })),
  )

  const encryptedData = await handleMultiModelBulkOperation(
    bulkEncryptPayload,
    (items) =>
      encryptBulk(client, {
        plaintexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  return models.map((_, modelIndex) => {
    const result: Record<string, unknown> = { ...otherFields[modelIndex] }

    // First, reconstruct the null/undefined fields
    for (const [key, value] of Object.entries(nullFields[modelIndex])) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    // Then, reconstruct the encrypted fields
    const modelData = Object.fromEntries(
      Object.entries(encryptedData)
        .filter(([key]) => {
          const [idx] = key.split('-')
          return Number.parseInt(idx) === modelIndex
        })
        .map(([key, value]) => {
          const [_, fieldKey] = key.split('-')
          return [fieldKey, value]
        }),
    )

    for (const [key, value] of Object.entries(modelData)) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    return result
  })
}

/**
 * Helper function to convert multiple models with encrypted fields to decrypted models
 */
export async function bulkDecryptModels<T extends Record<string, unknown>>(
  models: T[],
  client: Client,
  auditData?: AuditData,
): Promise<Decrypted<T>[]> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  if (!models || models.length === 0) {
    return []
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareBulkModelsForOperation(models)

  const bulkDecryptPayload = operationFields.flatMap((fields, modelIndex) =>
    Object.entries(fields).map(([key, value]) => ({
      id: `${modelIndex}-${key}`,
      ciphertext: value as CipherStashEncrypted,
    })),
  )

  const decryptedFields = await handleMultiModelBulkOperation(
    bulkDecryptPayload,
    (items) =>
      decryptBulk(client, {
        ciphertexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  return models.map((_, modelIndex) => {
    const result: Record<string, unknown> = { ...otherFields[modelIndex] }

    // First, reconstruct the null/undefined fields
    for (const [key, value] of Object.entries(nullFields[modelIndex])) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    // Then, reconstruct the decrypted fields
    const modelData = Object.fromEntries(
      Object.entries(decryptedFields)
        .filter(([key]) => {
          const [idx] = key.split('-')
          return Number.parseInt(idx) === modelIndex
        })
        .map(([key, value]) => {
          const [_, fieldKey] = key.split('-')
          return [fieldKey, value]
        }),
    )

    for (const [key, value] of Object.entries(modelData)) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    return result as Decrypted<T>
  })
}

/**
 * Helper function to convert multiple models with encrypted fields to decrypted models with lock context
 */
export async function bulkDecryptModelsWithLockContext<
  T extends Record<string, unknown>,
>(
  models: T[],
  client: Client,
  lockContext: GetLockContextResponse,
  auditData?: AuditData,
): Promise<Decrypted<T>[]> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  if (!lockContext) {
    throw new Error('Lock context is not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareBulkModelsForOperation(models)

  const bulkDecryptPayload = operationFields.flatMap((fields, modelIndex) =>
    Object.entries(fields).map(([key, value]) => ({
      id: `${modelIndex}-${key}`,
      ciphertext: value as CipherStashEncrypted,
      lockContext: lockContext.context,
    })),
  )

  const decryptedFields = await handleMultiModelBulkOperation(
    bulkDecryptPayload,
    (items) =>
      decryptBulk(client, {
        ciphertexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  // Reconstruct models
  return models.map((_, modelIndex) => {
    const result: Record<string, unknown> = { ...otherFields[modelIndex] }

    // First, reconstruct the null/undefined fields
    for (const [key, value] of Object.entries(nullFields[modelIndex])) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    // Then, reconstruct the decrypted fields
    const modelData = Object.fromEntries(
      Object.entries(decryptedFields)
        .filter(([key]) => {
          const [idx] = key.split('-')
          return Number.parseInt(idx) === modelIndex
        })
        .map(([key, value]) => {
          const [_, fieldKey] = key.split('-')
          return [fieldKey, value]
        }),
    )

    for (const [key, value] of Object.entries(modelData)) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    return result as Decrypted<T>
  })
}

/**
 * Helper function to convert multiple decrypted models to models with encrypted fields with lock context
 */
export async function bulkEncryptModelsWithLockContext(
  models: Record<string, unknown>[],
  table: EncryptedTable<EncryptedTableColumn>,
  client: Client,
  lockContext: GetLockContextResponse,
  auditData?: AuditData,
): Promise<Record<string, unknown>[]> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  if (!lockContext) {
    throw new Error('Lock context is not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareBulkModelsForOperation(models, table)

  const bulkEncryptPayload = operationFields.flatMap((fields, modelIndex) =>
    Object.entries(fields).map(([key, value]) => ({
      id: `${modelIndex}-${key}`,
      plaintext: value as string,
      table: table.tableName,
      column: key,
      lockContext: lockContext.context,
    })),
  )

  const encryptedData = await handleMultiModelBulkOperation(
    bulkEncryptPayload,
    (items) =>
      encryptBulk(client, {
        plaintexts: items,
        unverifiedContext: auditData?.metadata,
      }),
    keyMap,
  )

  // Reconstruct models
  return models.map((_, modelIndex) => {
    const result: Record<string, unknown> = { ...otherFields[modelIndex] }

    // First, reconstruct the null/undefined fields
    for (const [key, value] of Object.entries(nullFields[modelIndex])) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    // Then, reconstruct the encrypted fields
    const modelData = Object.fromEntries(
      Object.entries(encryptedData)
        .filter(([key]) => {
          const [idx] = key.split('-')
          return Number.parseInt(idx) === modelIndex
        })
        .map(([key, value]) => {
          const [_, fieldKey] = key.split('-')
          return [fieldKey, value]
        }),
    )

    for (const [key, value] of Object.entries(modelData)) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    return result
  })
}
