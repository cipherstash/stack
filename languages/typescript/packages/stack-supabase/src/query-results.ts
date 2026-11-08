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
 * An EQL payload as stored: {@link isEncryptedPayload} (the predicate model
 * decryption uses) plus the `i: { t, c }` table/column identifier every stored
 * envelope carries. The identifier check keeps a plaintext jsonb value that
 * merely has `v`, `i` and `c` keys from failing a read.
 */
function isStoredEnvelope(value: unknown): boolean {
  if (!isEncryptedPayload(value)) return false
  const id = (value as { i: unknown }).i as { t?: unknown; c?: unknown } | null
  return id !== null && typeof id.t === 'string' && typeof id.c === 'string'
}

/**
 * The key/index chain to the first EQL payload in `value`, or `null` if there
 * is none. The chain is built only on a hit, so the scan of a clean row — the
 * usual case — allocates nothing per value.
 */
function findEnvelope(value: unknown): Array<string | number> | null {
  if (isStoredEnvelope(value)) return []
  if (value === null || typeof value !== 'object') return null
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const found = findEnvelope(value[i])
      if (found !== null) return [i, ...found]
    }
    return null
  }
  for (const key in value) {
    const found = findEnvelope((value as Record<string, unknown>)[key])
    if (found !== null) return [key, ...found]
  }
  return null
}

/** Render a chain the way a caller wrote the select: `users[1].email`. */
function renderPath(chain: Array<string | number>): string {
  return chain
    .map((step, i) =>
      typeof step === 'number' ? `[${step}]` : i === 0 ? step : `.${step}`,
    )
    .join('')
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
function assertNoCiphertext(data: unknown, ctx: DecryptContext): void {
  for (const row of Array.isArray(data) ? data : [data]) {
    const chain = findEnvelope(row)
    if (chain === null) continue

    const message = `[supabase v3]: table "${ctx.tableName}" has no encrypted columns, but the result holds an encrypted value at "${renderPath(chain)}". It is not decrypted here: an embedded relation to an encrypted table is not supported (query that table directly), and in declared mode every encrypted column must be declared with a \`types.*\` factory.`
    throw new EncryptionFailedError(message, {
      type: EncryptionErrorTypes.DecryptionError,
      message,
    })
  }
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
  const respond = (data: TData | null): EncryptedSupabaseResponse<TData> => ({
    data,
    error: null,
    count: result.count ?? null,
    status: result.status,
    statusText: result.statusText,
  })

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
  if (result.data === null || result.data === undefined) return respond(null)

  // No select means no row data to decrypt (e.g. insert without .select()).
  if (ctx.selectColumns === null) return respond(result.data as TData)

  // A plaintext table has nothing to decrypt and is not registered with the
  // encryption client (see `tableHasEncryptedColumns`), so its rows are
  // returned as sent — once they are shown to hold no ciphertext.
  if (!ctx.columns.hasEncryptedColumns) {
    assertNoCiphertext(result.data, ctx)
    return respond(result.data as TData)
  }

  // Decrypt based on result mode
  if (ctx.resultMode === 'single' || ctx.resultMode === 'maybeSingle') {
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

    // ONE row — `TData` is `T` on this path (`single`/`maybeSingle` narrow it),
    // so no array wrapping and no cast pretending otherwise.
    return respond(
      postprocessDecryptedRow(
        decrypted.data as Record<string, unknown>,
        ctx,
      ) as TData,
    )
  }

  // Array result — bulk decrypt
  const dataArray = result.data as Record<string, unknown>[]
  if (dataArray.length === 0) return respond([] as TData)

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

  return respond(
    decrypted.data.map((row) =>
      postprocessDecryptedRow(row as Record<string, unknown>, ctx),
    ) as TData,
  )
}
