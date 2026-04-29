import fs from 'node:fs'
import path from 'node:path'
import { type ResolvedStashConfig, loadStashConfig } from '@/config/index.js'
import type { EncryptionClient } from '@cipherstash/stack/encryption'

/**
 * Structural shape of `@cipherstash/stack`'s `EncryptedTable` class.
 * Duck-typed so we don't need to `instanceof` across module boundaries
 * (which is fragile with dual CJS/ESM).
 */
export interface EncryptedTableLike {
  readonly tableName: string
  build(): { tableName: string; columns: Record<string, unknown> }
}

/**
 * Everything the encrypt commands need to do real work: resolved stash
 * config, the user's initialised encryption client, and a table-name-keyed
 * map of every `EncryptedTable` exported from the client file.
 */
export interface EncryptionContext {
  stashConfig: ResolvedStashConfig
  client: EncryptionClient
  tables: Map<string, EncryptedTableLike>
}

/**
 * Load `stash.config.ts`, dynamic-import the user's encryption client file
 * via jiti, and harvest:
 *
 * 1. The initialised `EncryptionClient` — detected by duck-typing any
 *    export that exposes a `getEncryptConfig()` method.
 * 2. Every `EncryptedTable` — detected by the pair of `tableName: string`
 *    and `build(): …` properties. Keyed by `tableName`.
 *
 * Both are needed by the backfill runner: the client to call
 * `bulkEncryptModels`, and the table schema to pass as the second arg.
 *
 * Exits the process with code `1` on any load error — the same hard-fail
 * behaviour `loadStashConfig` / `loadEncryptConfig` already use elsewhere
 * in the CLI.
 */
export async function loadEncryptionContext(): Promise<EncryptionContext> {
  const stashConfig = await loadStashConfig()
  const resolvedPath = path.resolve(process.cwd(), stashConfig.client)

  if (!fs.existsSync(resolvedPath)) {
    console.error(
      `Error: Encrypt client file not found at ${resolvedPath}\n\nCheck the "client" path in your stash.config.ts.`,
    )
    process.exit(1)
  }

  const { createJiti } = await import('jiti')
  const jiti = createJiti(resolvedPath, { interopDefault: true })

  let moduleExports: Record<string, unknown>
  try {
    moduleExports = (await jiti.import(resolvedPath)) as Record<string, unknown>
  } catch (error) {
    console.error(
      `Error: Failed to load encrypt client file at ${resolvedPath}\n`,
    )
    console.error(error)
    process.exit(1)
  }

  let client: EncryptionClient | undefined
  const tables = new Map<string, EncryptedTableLike>()
  const drizzleCandidates: unknown[] = []

  const DRIZZLE_NAME_SYMBOL = Symbol.for('drizzle:Name')

  for (const value of Object.values(moduleExports)) {
    if (!value || typeof value !== 'object') continue

    if (
      'getEncryptConfig' in value &&
      typeof (value as { getEncryptConfig?: unknown }).getEncryptConfig ===
        'function'
    ) {
      client = value as EncryptionClient
      continue
    }

    if (
      'tableName' in value &&
      typeof (value as { tableName?: unknown }).tableName === 'string' &&
      'build' in value &&
      typeof (value as { build?: unknown }).build === 'function'
    ) {
      const table = value as EncryptedTableLike
      tables.set(table.tableName, table)
      continue
    }

    // Drizzle pgTable — Symbol.for('drizzle:Name') is set by drizzle-orm
    // on anything constructed via `pgTable()`. We'll run extractEncryptionSchema
    // on these in a second pass.
    if ((value as Record<symbol, unknown>)[DRIZZLE_NAME_SYMBOL] !== undefined) {
      drizzleCandidates.push(value)
    }
  }

  // Second pass: auto-derive EncryptedTable schemas from drizzle pgTable
  // exports so users don't have to manually export the result of
  // extractEncryptionSchema(). Silently no-op if @cipherstash/stack/drizzle
  // isn't installed (e.g. a Supabase-only project).
  if (drizzleCandidates.length > 0) {
    try {
      const drizzleModule = (await import('@cipherstash/stack/drizzle')) as {
        extractEncryptionSchema?: (t: unknown) => EncryptedTableLike
      }
      const extract = drizzleModule.extractEncryptionSchema
      if (extract) {
        for (const candidate of drizzleCandidates) {
          try {
            const derived = extract(candidate)
            if (derived?.tableName && !tables.has(derived.tableName)) {
              tables.set(derived.tableName, derived)
            }
          } catch {
            // Table has no encrypted columns, or extraction failed for
            // another reason. Ignore — not every drizzle table is a
            // backfill target.
          }
        }
      }
    } catch {
      // @cipherstash/stack/drizzle not installed; skip drizzle fallback.
    }
  }

  if (!client) {
    console.error(
      `Error: No EncryptionClient export found in ${stashConfig.client}.`,
    )
    process.exit(1)
  }

  return { stashConfig, client, tables }
}

/**
 * Look up the `EncryptedTable` for the given table name in the loaded
 * context. Exits the process with code `1` if the table is not declared
 * in the user's encryption client file — without this schema, backfill
 * cannot call `bulkEncryptModels`.
 */
export function requireTable(
  ctx: EncryptionContext,
  tableName: string,
): EncryptedTableLike {
  const table = ctx.tables.get(tableName)
  if (!table) {
    const available = Array.from(ctx.tables.keys()).join(', ') || '(none)'
    console.error(
      `Error: Table "${tableName}" was not found in the encryption client exports.\n` +
        `Available: ${available}`,
    )
    process.exit(1)
  }
  return table
}
