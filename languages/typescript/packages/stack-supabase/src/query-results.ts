import {
  DATE_LIKE_CASTS,
  isEncryptedPayload,
  logger,
  reconstructDatePaths,
  reconstructDateValue,
} from '@cipherstash/stack/adapter-kit'
import { EncryptionErrorTypes } from '@cipherstash/stack/errors'
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
  // Dotted paths are collected and reconstructed in ONE pass:
  // `reconstructDatePaths` allocates a fresh shallow row copy per call, so
  // calling it per key spent one clone on every nested date column. Batching
  // is also what keeps two paths sharing a prefix (`profile.createdAt` /
  // `profile.updatedAt`) correct — within a single call the second path clones
  // the intermediate the first already rebuilt, rather than the raw source.
  const dottedKeys: string[] = []
  for (const [key, dbName] of Object.entries(keyToDb)) {
    const castAs = ctx.columns.schemaFor(dbName)?.cast_as
    if (!DATE_LIKE_CAST_SET.has(castAs as string)) continue
    if (key.includes('.')) {
      dottedKeys.push(key)
    } else if (Object.hasOwn(out, key)) {
      out[key] = reconstructDateValue(out[key])
    }
  }
  return dottedKeys.length > 0 ? reconstructDatePaths(out, dottedKeys) : out
}

/**
 * The path of the first EQL payload anywhere in `value`, or `null` if there is
 * none. Paths read the way a caller wrote the select: `users.email`, or
 * `users[1].email` inside an embedded to-many relation.
 */
function findEncryptedPayload(value: unknown, path: string): string | null {
  if (isEncryptedPayload(value)) return path
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const found = findEncryptedPayload(value[i], `${path}[${i}]`)
      if (found !== null) return found
    }
    return null
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const found = findEncryptedPayload(child, path ? `${path}.${key}` : key)
      if (found !== null) return found
    }
  }
  return null
}

/**
 * Refuse a plaintext table's rows if any of them carries ciphertext.
 *
 * A table with no encrypted columns skips decryption, but its rows can still
 * hold an EQL payload: from an embedded relation to an encrypted table
 * (`select('id, users(email)')`), or from a table declared with `{}` in declared
 * mode whose real columns are `eql_v3_*` domains. Passing those through would
 * hand the caller ciphertext typed as data — the hazard `assertTableIsModelled`
 * exists to prevent — so fail instead. The message names the path, never the
 * value.
 */
function assertNoCiphertext(rows: unknown, ctx: DecryptContext): void {
  const path = Array.isArray(rows)
    ? rows.reduce<string | null>(
        (found, row) => found ?? findEncryptedPayload(row, ''),
        null,
      )
    : findEncryptedPayload(rows, '')
  if (path === null) return

  const message = `[supabase v3]: table "${ctx.tableName}" has no encrypted columns, but the result holds an encrypted value at "${path}". It is not decrypted here: an embedded relation to an encrypted table is not supported (query that table directly), and in declared mode every encrypted column must be declared with a \`types.*\` factory.`
  throw new EncryptionFailedError(message, {
    type: EncryptionErrorTypes.DecryptionError,
    message,
  })
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
export async function decryptResults<T extends object, TData = T[]>(
  result: RawSupabaseResult,
  ctx: DecryptContext,
): Promise<EncryptedSupabaseResponse<TData>> {
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

  if (hasSelect && !ctx.columns.hasEncryptedColumns) {
    // A plaintext table (no encrypted columns) has nothing to decrypt, and is
    // not registered with the encryption client either — both engines would
    // refuse it as "a table this client was not initialized with" (see
    // `tableHasEncryptedColumns`). Nor is there a `Date` to rebuild:
    // `postprocessDecryptedRow` only touches encrypted columns. Return the rows
    // as PostgREST sent them, once they are shown to hold no ciphertext.
    assertNoCiphertext(result.data, ctx)
    return {
      data: result.data as TData,
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  if (!hasSelect && !hasMutationWithReturning) {
    // No select means no data to decrypt (e.g., insert without .select())
    return {
      data: result.data as TData,
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
      // The table is passed for the WASM engine, which resolves date fields
      // from a per-table map and throws without it. The native client derives
      // the table from the payloads and ignores the extra argument, so one
      // call shape serves both entries (#708).
      ctx.encryptionClient.decryptModel(
        result.data as Record<string, unknown>,
        ctx.table,
      ),
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
      // ONE row — `TData` is `T` on this path (`single`/`maybeSingle` narrow it),
      // so no array wrapping and no cast pretending otherwise.
      data: postprocessDecryptedRow(
        decrypted.data as Record<string, unknown>,
        ctx,
      ) as TData,
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
      data: [] as TData,
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  const decrypted = await withOpContext(
    // Table passed for the same reason as the single-row path above.
    ctx.encryptionClient.bulkDecryptModels(dataArray, ctx.table),
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
    ) as TData,
    error: null,
    count: result.count ?? null,
    status: result.status,
    statusText: result.statusText,
  }
}
