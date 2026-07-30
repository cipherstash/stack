import fs from 'node:fs'
import path from 'node:path'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import { detectPrismaNext } from '@/commands/db/detect.js'
import {
  loadStashConfig,
  type ResolvedStashConfig,
  requireUsableEncryptConfig,
} from '@/config/index.js'

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
    // Prisma Next projects have no hand-authored encryption client — the
    // schema lives in the emitted contract.json and the runtime derives it
    // via `cipherstashFromStack`. Mirror that derivation here so the encrypt
    // commands work without asking users to author a bridge file.
    const derived = await tryLoadPrismaNextContext(stashConfig)
    if (derived) return derived

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
  // extractEncryptionSchema(). Silently no-op if @cipherstash/stack-drizzle
  // isn't installed (e.g. a Supabase-only project).
  if (drizzleCandidates.length > 0) {
    try {
      const drizzleModule = (await import('@cipherstash/stack-drizzle')) as {
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
      // @cipherstash/stack-drizzle not installed; skip drizzle fallback.
    }
  }

  if (!client) {
    console.error(
      `Error: No EncryptionClient export found in ${stashConfig.client}.`,
    )
    process.exit(1)
  }

  // The same refusal `stash db validate` gets from
  // `loadEncryptConfig`, applied here because `stash encrypt` does not go
  // through that loader. Called, not re-implemented: it guards one file, so the
  // two commands must say one thing about it. Without this, `requireTable`
  // reported `Table "users" was not found … Available: __stash_placeholder__`,
  // naming the symptom and not the cause (#787 review).
  requireUsableEncryptConfig(client.getEncryptConfig(), stashConfig.client)

  return { stashConfig, client, tables }
}

/**
 * Well-known locations for a Prisma Next emitted contract, relative to the
 * project root. `prisma-next contract emit` writes `contract.json` next to
 * the authored contract, which the scaffolds place under `src/prisma/` or
 * `prisma/`.
 */
const PRISMA_NEXT_CONTRACT_CANDIDATES = [
  'src/prisma/contract.json',
  'prisma/contract.json',
  'contract.json',
]

/**
 * Derive an `EncryptionContext` for a Prisma Next project — the fallback
 * used when the configured encrypt client file does not exist.
 *
 * Prisma Next integrations deliberately have no client file: encrypted
 * columns are declared in the PSL contract, and the runtime adapter derives
 * the v3 schemas from the emitted `contract.json` (`deriveStackSchemasV3`)
 * before constructing the same `Encryption` client this function builds.
 * Reusing that derivation keeps the CLI's view of the schema identical to
 * the application's.
 *
 * Returns `undefined` when the project doesn't look like Prisma Next, so
 * the caller can fall through to its existing missing-client error. Inside
 * a detected Prisma Next project, failures are hard errors (exit 1) with
 * the specific missing piece named — falling through to "client file not
 * found" from here would point users at a file they are not supposed to
 * author.
 *
 * Both `@cipherstash/stack-prisma` and `@cipherstash/stack` are resolved
 * from the *user's* project (via jiti anchored at their package.json), not
 * from the CLI's own dependency tree, so the derived schemas and client
 * always match the versions the application runs.
 */
async function tryLoadPrismaNextContext(
  stashConfig: ResolvedStashConfig,
): Promise<EncryptionContext | undefined> {
  const cwd = process.cwd()
  if (!detectPrismaNext(cwd)) return undefined

  const contractPath = PRISMA_NEXT_CONTRACT_CANDIDATES.map((candidate) =>
    path.resolve(cwd, candidate),
  ).find((candidate) => fs.existsSync(candidate))
  if (!contractPath) {
    console.error(
      `Error: This looks like a Prisma Next project, but no emitted contract was found.\n` +
        `Searched: ${PRISMA_NEXT_CONTRACT_CANDIDATES.join(', ')}\n\n` +
        'Run `prisma-next contract emit` first. (Or point "client" in stash.config.ts at an encryption client file to skip contract derivation.)',
    )
    process.exit(1)
  }

  const { createJiti } = await import('jiti')
  const jiti = createJiti(path.join(cwd, 'package.json'), {
    interopDefault: true,
  })

  let deriveStackSchemasV3: (contract: unknown) => readonly unknown[]
  let Encryption: (opts: {
    schemas: readonly unknown[]
  }) => Promise<EncryptionClient>
  try {
    const stackPrismaV3 = (await jiti.import(
      '@cipherstash/stack-prisma/v3',
    )) as {
      deriveStackSchemasV3: typeof deriveStackSchemasV3
    }
    deriveStackSchemasV3 = stackPrismaV3.deriveStackSchemasV3
    const stackV3 = (await jiti.import('@cipherstash/stack/v3')) as {
      Encryption: typeof Encryption
    }
    Encryption = stackV3.Encryption
  } catch (error) {
    console.error(
      'Error: Failed to load @cipherstash/stack-prisma / @cipherstash/stack from this project.\n' +
        'Both must be installed to run encrypt commands against a Prisma Next contract.\n',
    )
    console.error(error)
    process.exit(1)
  }

  let schemas: readonly unknown[]
  try {
    const contractJson = JSON.parse(
      fs.readFileSync(contractPath, 'utf-8'),
    ) as unknown
    schemas = deriveStackSchemasV3(contractJson)
  } catch (error) {
    // deriveStackSchemasV3's own errors are author-facing and name the
    // offending column; JSON.parse errors name the broken file below.
    console.error(
      `Error: Failed to derive encryption schemas from ${contractPath}\n`,
    )
    console.error(error)
    process.exit(1)
  }

  // `deriveStackSchemasV3` is typed from a jiti import, so its return value is
  // an assertion, not a checked fact. A version skew that renamed or reshaped
  // the export would hand us `undefined` here, and the `.length` read below
  // would throw a raw TypeError past all of this guidance (#819 review).
  if (!Array.isArray(schemas)) {
    console.error(
      `Error: @cipherstash/stack-prisma's deriveStackSchemasV3 returned ${typeof schemas}, not an array of tables.\n\n` +
        "This usually means the installed @cipherstash/stack-prisma doesn't match this CLI release. Align the versions and re-run.",
    )
    process.exit(1)
  }

  if (schemas.length === 0) {
    console.error(
      `Error: No cipherstash-encrypted columns found in ${contractPath}.\n\n` +
        'Declare at least one `cipherstash.*()` column in your contract and re-run `prisma-next contract emit`.',
    )
    process.exit(1)
  }

  const client = await Encryption({ schemas })
  requireUsableEncryptConfig(
    client.getEncryptConfig(),
    contractPath,
    `Encryption schemas derived from ${contractPath}`,
  )

  const tables = new Map<string, EncryptedTableLike>()
  for (const schema of schemas as EncryptedTableLike[]) {
    tables.set(schema.tableName, schema)
  }

  return { stashConfig, client, tables }
}

/**
 * Look up the `EncryptedTable` for the given table name in the loaded
 * context. Exits the process with code `1` if the table is not declared
 * in the user's encryption client file — without this schema, backfill
 * cannot call `bulkEncryptModels`.
 *
 * Accepts schema-qualified inputs (`public.users`) and falls back to the
 * unqualified name when no exact match is found — `EncryptedTable.tableName`
 * is typically declared without a schema, so `public.users` should still
 * resolve to a table whose `tableName === 'users'`.
 */
export function requireTable(
  ctx: EncryptionContext,
  tableName: string,
): EncryptedTableLike {
  const direct = ctx.tables.get(tableName)
  if (direct) return direct

  const dot = tableName.lastIndexOf('.')
  if (dot >= 0) {
    const unqualified = tableName.slice(dot + 1)
    const fallback = ctx.tables.get(unqualified)
    if (fallback) return fallback
  }

  const available = Array.from(ctx.tables.keys()).join(', ') || '(none)'
  console.error(
    `Error: Table "${tableName}" was not found in the encryption client exports.\n` +
      `Available: ${available}`,
  )
  process.exit(1)
}
