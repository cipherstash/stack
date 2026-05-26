import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import { ProtectError as FfiProtectError } from '@cipherstash/protect-ffi'
import type { EncryptedDynamoDBError } from './types'

export const ciphertextAttrSuffix = '__source'
export const searchTermAttrSuffix = '__hmac'

export class EncryptedDynamoDBErrorImpl
  extends Error
  implements EncryptedDynamoDBError
{
  constructor(
    message: string,
    public code: ProtectErrorCode | 'DYNAMODB_ENCRYPTION_ERROR',
    public details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'EncryptedDynamoDBError'
  }
}

export function handleError(
  error: unknown,
  context: string,
  options?: {
    logger?: {
      error: (message: string, error: Error) => void
    }
    errorHandler?: (error: EncryptedDynamoDBError) => void
  },
): EncryptedDynamoDBError {
  // Preserve FFI error code if available, otherwise use generic DynamoDB error code
  // Check for FfiProtectError instance or plain error objects with code property
  const errorObj = error as Record<string, unknown>
  const errorCode =
    error instanceof FfiProtectError
      ? error.code
      : errorObj &&
          typeof errorObj === 'object' &&
          'code' in errorObj &&
          typeof errorObj.code === 'string'
        ? (errorObj.code as ProtectErrorCode)
        : 'DYNAMODB_ENCRYPTION_ERROR'

  const errorMessage =
    error instanceof Error
      ? error.message
      : errorObj && typeof errorObj.message === 'string'
        ? errorObj.message
        : String(error)

  const dynamoError = new EncryptedDynamoDBErrorImpl(errorMessage, errorCode, {
    context,
  })

  logger.error(`DynamoDB error in ${context}: ${errorMessage}`)

  if (options?.errorHandler) {
    options.errorHandler(dynamoError)
  }

  if (options?.logger) {
    options.logger.error(`Error in ${context}`, dynamoError)
  }

  return dynamoError
}

export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => deepClone(item)) as unknown as T
  }

  return Object.entries(obj as Record<string, unknown>).reduce(
    (acc, [key, value]) => ({
      // biome-ignore lint/performance/noAccumulatingSpread: TODO later
      ...acc,
      [key]: deepClone(value),
    }),
    {} as T,
  )
}

export function toEncryptedDynamoItem(
  encrypted: Record<string, unknown>,
  encryptedAttrs: string[],
): Record<string, unknown> {
  function processValue(
    attrName: string,
    attrValue: unknown,
    isNested: boolean,
  ): Record<string, unknown> {
    if (attrValue === null || attrValue === undefined) {
      return { [attrName]: attrValue }
    }

    // Handle encrypted payload
    if (
      encryptedAttrs.includes(attrName) ||
      (isNested &&
        typeof attrValue === 'object' &&
        'c' in (attrValue as object))
    ) {
      const encryptPayload = attrValue as EncryptedValue
      if (encryptPayload?.k === 'ct' && encryptPayload.c) {
        const result: Record<string, unknown> = {}
        if (encryptPayload.hm) {
          result[`${attrName}${searchTermAttrSuffix}`] = encryptPayload.hm
        }
        result[`${attrName}${ciphertextAttrSuffix}`] = encryptPayload.c
        return result
      }

      if (encryptPayload?.k === 'sv' && encryptPayload.sv) {
        const result: Record<string, unknown> = {}
        result[`${attrName}${ciphertextAttrSuffix}`] = encryptPayload.sv
        return result
      }
    }

    // Handle nested objects recursively
    if (typeof attrValue === 'object' && !Array.isArray(attrValue)) {
      const nestedResult = Object.entries(
        attrValue as Record<string, unknown>,
      ).reduce(
        (acc, [key, val]) => {
          const processed = processValue(key, val, true)
          return Object.assign({}, acc, processed)
        },
        {} as Record<string, unknown>,
      )
      return { [attrName]: nestedResult }
    }

    // Handle non-encrypted values
    return { [attrName]: attrValue }
  }

  return Object.entries(encrypted).reduce(
    (putItem, [attrName, attrValue]) => {
      const processed = processValue(attrName, attrValue, false)
      return Object.assign({}, putItem, processed)
    },
    {} as Record<string, unknown>,
  )
}

export function toItemWithEqlPayloads(
  decrypted: Record<string, EncryptedValue | unknown>,
  encryptionSchema: EncryptedTable<EncryptedTableColumn>,
): Record<string, unknown> {
  function processValue(
    attrName: string,
    attrValue: unknown,
    isNested: boolean,
  ): Record<string, unknown> {
    if (attrValue === null || attrValue === undefined) {
      return { [attrName]: attrValue }
    }

    // Skip HMAC fields
    if (attrName.endsWith(searchTermAttrSuffix)) {
      return {}
    }

    const encryptConfig = encryptionSchema.build()
    const encryptedAttrs = Object.keys(encryptConfig.columns)
    const columnName = attrName.slice(0, -ciphertextAttrSuffix.length)

    // Handle encrypted payload
    if (
      attrName.endsWith(ciphertextAttrSuffix) &&
      (encryptedAttrs.includes(columnName) || isNested)
    ) {
      const i = { c: columnName, t: encryptConfig.tableName }
      const v = 2

      // Nested values are not searchable, so we can just return the standard EQL payload.
      // Worth noting, that encryptConfig.columns[columnName] will be undefined if isNested is true.
      if (
        !isNested &&
        encryptConfig.columns[columnName].cast_as === 'json' &&
        encryptConfig.columns[columnName].indexes.ste_vec
      ) {
        return {
          [columnName]: {
            i,
            v,
            k: 'sv',
            sv: attrValue,
          },
        }
      }

      return {
        [columnName]: {
          i,
          v,
          k: 'ct',
          c: attrValue,
        },
      }
    }

    // Handle nested objects recursively
    if (typeof attrValue === 'object' && !Array.isArray(attrValue)) {
      const nestedResult = Object.entries(
        attrValue as Record<string, unknown>,
      ).reduce(
        (acc, [key, val]) => {
          const processed = processValue(key, val, true)
          return Object.assign({}, acc, processed)
        },
        {} as Record<string, unknown>,
      )
      return { [attrName]: nestedResult }
    }

    // Handle non-encrypted values
    return { [attrName]: attrValue }
  }

  return Object.entries(decrypted).reduce(
    (formattedItem, [attrName, attrValue]) => {
      const processed = processValue(attrName, attrValue, false)
      return Object.assign({}, formattedItem, processed)
    },
    {} as Record<string, unknown>,
  )
}
