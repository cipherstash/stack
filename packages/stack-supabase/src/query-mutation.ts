import { logger } from '@cipherstash/stack/adapter-kit'
import type { ColumnMap } from './column-map'
import {
  type EncryptionContext,
  EncryptionFailedError,
  withOpContext,
} from './query-encrypt'
import type { MutationOp } from './types'

/**
 * Encode an encrypted model for the Supabase request body. The native
 * `eql_v3.*` domains are plain jsonb, so the raw encrypted payload is sent
 * (keyed by DB column name).
 */
function transformEncryptedMutationModel(
  model: Record<string, unknown>,
  columns: ColumnMap,
): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null)
  for (const [key, value] of Object.entries(model)) {
    out[columns.dbNameFor(key)] = value
  }
  return out
}

/**
 * Encrypt a mutation's row data — the values being STORED, as opposed to the
 * filter operands being searched by (`./query-encrypt`). `delete` carries no
 * data, and a builder with no recorded mutation encrypts nothing.
 */
export async function encryptMutationData(
  mutation: MutationOp | null,
  ctx: EncryptionContext,
): Promise<Record<string, unknown> | Record<string, unknown>[] | null> {
  if (!mutation) return null
  if (mutation.kind === 'delete') return null

  const data = mutation.data

  if (Array.isArray(data)) {
    // Bulk encrypt
    const result = await withOpContext(
      ctx.encryptionClient.bulkEncryptModels(data, ctx.table),
      ctx,
    )
    if (result.failure) {
      logger.error(
        `Supabase: failed to encrypt models for table "${ctx.tableName}"`,
      )

      throw new EncryptionFailedError(
        `Failed to encrypt models: ${result.failure.message}`,
        result.failure,
      )
    }

    return result.data.map((model) =>
      transformEncryptedMutationModel(model, ctx.columns),
    )
  }

  // Single model
  const result = await withOpContext(
    ctx.encryptionClient.encryptModel(data, ctx.table),
    ctx,
  )
  if (result.failure) {
    logger.error(
      `Supabase: failed to encrypt model for table "${ctx.tableName}"`,
    )

    throw new EncryptionFailedError(
      `Failed to encrypt model: ${result.failure.message}`,
      result.failure,
    )
  }

  return transformEncryptedMutationModel(result.data, ctx.columns)
}
