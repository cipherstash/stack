import { DATE_LIKE_CASTS, logger } from '@cipherstash/stack/adapter-kit'
import { selectKeyToDbV3 } from './helpers'
import {
  type EncryptionContext,
  EncryptionFailedError,
  withOpContext,
} from './query-encrypt'
import type { EncryptedSupabaseResponse, ResultMode } from './types'

/** cast_as kinds that reconstruct to a JS `Date` — shared with the typed v3
 * client's decrypt-model path (see `encryption/v3.ts`). */
const DATE_LIKE_CAST_SET = new Set<string>(DATE_LIKE_CASTS)

export type RawSupabaseResult = {
  data: unknown
  error: {
    message: string
    details?: string
    hint?: string
    code?: string
  } | null
  count?: number | null
  status: number
  statusText: string
}

/** What the decrypt step needs beyond the shared encryption context. */
export type DecryptContext = EncryptionContext & {
  selectColumns: string | null
  resultMode: ResultMode
  hasMutation: boolean
}

/**
 * Post-process a decrypted result row: rebuild `Date` values from the
 * encrypt-config `cast_as` (date/timestamp), mirroring the typed v3 client's
 * decrypt-model path.
 */
function postprocessDecryptedRow(
  row: Record<string, unknown>,
  ctx: DecryptContext,
): Record<string, unknown> {
  // Every key an encrypted column can appear under: the keys this select
  // actually produces (including caller-chosen aliases like `ts:createdAt`),
  // plus the static property and DB names as a fallback for paths that record
  // no select. Aliases win. Derived here from `ctx.selectColumns` (the row in
  // hand) rather than cached from `buildSelectString`, so a reused builder can
  // never postprocess a row with a previous operation's stale select map.
  const propToDb = ctx.columns.propToDb
  const keyToDb: Record<string, string> = Object.assign(
    Object.create(null),
    ctx.selectColumns === null
      ? undefined
      : selectKeyToDbV3(ctx.selectColumns, propToDb),
  )
  for (const [property, dbName] of Object.entries(propToDb)) {
    keyToDb[property] ??= dbName
    keyToDb[dbName] ??= dbName
  }

  const out: Record<string, unknown> = { ...row }
  for (const [key, dbName] of Object.entries(keyToDb)) {
    const castAs = ctx.columns.schemaFor(dbName)?.cast_as
    if (!DATE_LIKE_CAST_SET.has(castAs as string)) continue
    const value = out[key]
    if (value == null || value instanceof Date) continue
    if (typeof value === 'string' || typeof value === 'number') {
      out[key] = new Date(value)
    }
  }
  return out
}

/**
 * Decrypt a PostgREST response into the caller's row type.
 *
 * Reads EQL v3 only. A column carrying legacy EQL v2 ciphertext is never in
 * this adapter's encrypt config — introspection recognises `public.eql_v3_*`
 * domains exclusively — so it is returned as an untouched passthrough rather
 * than decrypted. To read v2 data, decrypt fetched rows with the core
 * `@cipherstash/stack` client, whose decrypt path is generation-agnostic.
 */
export async function decryptResults<T extends Record<string, unknown>>(
  result: RawSupabaseResult,
  ctx: DecryptContext,
): Promise<EncryptedSupabaseResponse<T[]>> {
  // If there's an error from Supabase, pass it through
  if (result.error) {
    return {
      data: null,
      error: {
        message: result.error.message,
        details: result.error.details,
        hint: result.error.hint,
        code: result.error.code,
      },
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  // No data to decrypt
  if (result.data === null || result.data === undefined) {
    return {
      data: null,
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  // Determine if we need to decrypt
  const hasSelect = ctx.selectColumns !== null
  const hasMutationWithReturning = ctx.hasMutation && hasSelect

  if (!hasSelect && !hasMutationWithReturning) {
    // No select means no data to decrypt (e.g., insert without .select())
    return {
      data: result.data as T[],
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  // Decrypt based on result mode
  if (ctx.resultMode === 'single' || ctx.resultMode === 'maybeSingle') {
    if (result.data === null) {
      return {
        data: null,
        error: null,
        count: result.count ?? null,
        status: result.status,
        statusText: result.statusText,
      }
    }

    // Single result — decrypt one model
    const decrypted = await withOpContext(
      ctx.encryptionClient.decryptModel(result.data as Record<string, unknown>),
      ctx,
    )
    if (decrypted.failure) {
      logger.error(
        `Supabase: failed to decrypt model for table "${ctx.tableName}"`,
      )

      throw new EncryptionFailedError(
        `Failed to decrypt model: ${decrypted.failure.message}`,
        decrypted.failure,
      )
    }

    return {
      data: postprocessDecryptedRow(
        decrypted.data as Record<string, unknown>,
        ctx,
      ) as unknown as T[],
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  // Array result — bulk decrypt
  const dataArray = result.data as Record<string, unknown>[]
  if (dataArray.length === 0) {
    return {
      data: [] as unknown as T[],
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  const decrypted = await withOpContext(
    ctx.encryptionClient.bulkDecryptModels(dataArray),
    ctx,
  )
  if (decrypted.failure) {
    logger.error(
      `Supabase: failed to decrypt models for table "${ctx.tableName}"`,
    )

    throw new EncryptionFailedError(
      `Failed to decrypt models: ${decrypted.failure.message}`,
      decrypted.failure,
    )
  }

  return {
    data: decrypted.data.map((row) =>
      postprocessDecryptedRow(row as Record<string, unknown>, ctx),
    ) as unknown as T[],
    error: null,
    count: result.count ?? null,
    status: result.status,
    statusText: result.statusText,
  }
}
