import { isEncryptedPayload } from '@/encryption/helpers'
import { assertValidNumericValue } from '@/encryption/helpers/validation'
import type { BuildableTable } from '@/types'

/**
 * The pure model-traversal layer shared by BOTH encryption entries: the
 * native model helpers (`./model-helpers`, which pair it with the NAPI
 * `encryptBulk`/`decryptBulk`) and the WASM entry (`@/wasm-inline`, which
 * pairs it with the `/wasm-inline` FFI batch calls — #742).
 *
 * Extracted so the walk itself cannot drift between entries. The traversal is
 * where the quiet plaintext-leak class of bug lives — a schema field the walk
 * fails to match is passed through UNENCRYPTED — so there must be exactly one
 * implementation of it.
 *
 * MUST stay free of runtime `@cipherstash/protect-ffi` imports (type-only is
 * fine): this module is bundled into `dist/wasm-inline.js`, whose whole point
 * is to not touch the native binding. `__tests__/wasm-inline-bundle-isolation`
 * enforces that at the artifact level.
 */

/**
 * Sets a value at a nested path in an object, creating intermediate objects as needed.
 * Includes prototype pollution protection.
 */
export function setNestedValue(
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
 * Resolve how a table's model fields map onto encrypt-config columns.
 *
 * `columnPaths` are the keys used to MATCH a user model's fields (the JS
 * property names); `toColumnName` maps a matched field to the name the FFI /
 * encrypt config is keyed by (the DB name).
 *
 * When a table exposes `buildColumnKeyMap()` (v3), those two can differ, so we
 * match by property but address by DB name. Otherwise (v2) `build()` already
 * keys columns by the property name, so both are that same key (identity map).
 */
export function resolveEncryptColumnMap(table: BuildableTable): {
  columnPaths: string[]
  toColumnName: (path: string) => string
} {
  const keyMap = table.buildColumnKeyMap?.()
  if (keyMap) {
    return {
      columnPaths: Object.keys(keyMap),
      toColumnName: (path) => keyMap[path] ?? path,
    }
  }
  const columnPaths = Object.keys(table.build().columns)
  return { columnPaths, toColumnName: (path) => path }
}

/**
 * Helper function to prepare fields for decryption
 */
export function prepareFieldsForDecryption<T extends Record<string, unknown>>(
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
export function prepareFieldsForEncryption<T extends Record<string, unknown>>(
  model: T,
  table: BuildableTable,
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
        // Only process fields that are explicitly defined in the schema.
        // Reject an out-of-range numeric plaintext (NaN/±Infinity for `number`,
        // outside i64 for `bigint`) here — the single-value/query paths guard
        // at their own boundary, but the model path builds the FFI payload
        // directly, so validate per field before it reaches protect-ffi.
        assertValidNumericValue(value)
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

  // Get all column paths from the table schema (matched by JS property name).
  const { columnPaths } = resolveEncryptColumnMap(table)
  processNestedFields(model, '', columnPaths)

  return { otherFields, operationFields, keyMap, nullFields }
}

/**
 * Helper function to prepare multiple models for bulk operation
 */
export function prepareBulkModelsForOperation<
  T extends Record<string, unknown>,
>(
  models: T[],
  table?: BuildableTable,
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
          // Only process fields that are explicitly defined in the schema.
          // Reject an out-of-range numeric plaintext (NaN/±Infinity for
          // `number`, outside i64 for `bigint`) before it reaches the bulk FFI
          // payload — the bulk path builds that payload directly. This arm runs
          // only for encryption (`if (table)`); the decrypt walker below does
          // not validate.
          assertValidNumericValue(value)
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
      // Get all column paths from the table schema (matched by JS property name).
      const { columnPaths } = resolveEncryptColumnMap(table)
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
 * Collect the per-model fields out of a bulk-operation result map keyed by
 * `${modelIndex}-${fieldKey}` ids, splitting each id at the FIRST hyphen
 * only. Field keys may themselves contain hyphens (a `some-field` column, or
 * a nested `profile.some-field` path), so a naive `split('-')` would truncate
 * the field key at its first hyphen and silently drop the value during model
 * reconstruction.
 */
export function fieldsForModelIndex(
  fields: Record<string, unknown>,
  modelIndex: number,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [id, value] of Object.entries(fields)) {
    const sep = id.indexOf('-')
    if (Number.parseInt(id.slice(0, sep), 10) !== modelIndex) continue
    result[id.slice(sep + 1)] = value
  }
  return result
}
