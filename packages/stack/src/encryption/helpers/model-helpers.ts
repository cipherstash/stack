import {
  type Encrypted as CipherStashEncrypted,
  decryptBulk,
  encryptBulk,
} from '@cipherstash/protect-ffi'
import { isEncryptedPayload } from '@/encryption/helpers'
import {
  fieldsForModelIndex,
  prepareBulkModelsForOperation,
  prepareFieldsForDecryption,
  prepareFieldsForEncryption,
  resolveEncryptColumnMap,
  setNestedValue,
} from '@/encryption/helpers/model-traversal'
import type { AuditData } from '@/encryption/operations/base-operation'
import type { Context } from '@/identity'
import type { BuildableTable, Client, Decrypted, Encrypted } from '@/types'

// The traversal layer (field matching, null bookkeeping, nested placement)
// lives in `./model-traversal` so the WASM entry shares it verbatim — see that
// module's header. This module pairs it with the NATIVE protect-ffi batch
// calls and the lock-context variants. `resolveEncryptColumnMap` is re-exported
// because it is part of this module's documented surface.
export { resolveEncryptColumnMap } from '@/encryption/helpers/model-traversal'

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
  table: BuildableTable,
  client: Client,
  auditData?: AuditData,
): Promise<Record<string, unknown>> {
  if (!client) {
    throw new Error('Client not initialized')
  }

  const { otherFields, operationFields, keyMap, nullFields } =
    prepareFieldsForEncryption(model, table)

  const { toColumnName } = resolveEncryptColumnMap(table)
  const bulkEncryptPayload = Object.entries(operationFields).map(
    ([key, value]) => ({
      id: key,
      plaintext: value as string,
      table: table.tableName,
      column: toColumnName(key),
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
  lockContext: Context,
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
      lockContext,
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
  table: BuildableTable,
  client: Client,
  lockContext: Context,
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

  const { toColumnName } = resolveEncryptColumnMap(table)
  const bulkEncryptPayload = Object.entries(operationFields).map(
    ([key, value]) => ({
      id: key,
      plaintext: value as string,
      table: table.tableName,
      column: toColumnName(key),
      lockContext,
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
 * Helper function to convert multiple decrypted models to models with encrypted fields
 */
export async function bulkEncryptModels(
  models: Record<string, unknown>[],
  table: BuildableTable,
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

  const { toColumnName } = resolveEncryptColumnMap(table)
  const bulkEncryptPayload = operationFields.flatMap((fields, modelIndex) =>
    Object.entries(fields).map(([key, value]) => ({
      id: `${modelIndex}-${key}`,
      plaintext: value as string,
      table: table.tableName,
      column: toColumnName(key),
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
    const modelData = fieldsForModelIndex(encryptedData, modelIndex)

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
    const modelData = fieldsForModelIndex(decryptedFields, modelIndex)

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
  lockContext: Context,
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
      lockContext,
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
    const modelData = fieldsForModelIndex(decryptedFields, modelIndex)

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
  table: BuildableTable,
  client: Client,
  lockContext: Context,
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

  const { toColumnName } = resolveEncryptColumnMap(table)
  const bulkEncryptPayload = operationFields.flatMap((fields, modelIndex) =>
    Object.entries(fields).map(([key, value]) => ({
      id: `${modelIndex}-${key}`,
      plaintext: value as string,
      table: table.tableName,
      column: toColumnName(key),
      lockContext,
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
    const modelData = fieldsForModelIndex(encryptedData, modelIndex)

    for (const [key, value] of Object.entries(modelData)) {
      const parts = key.split('.')
      setNestedValue(result, parts, value)
    }

    return result
  })
}
