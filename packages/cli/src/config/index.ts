import fs from 'node:fs'
import path from 'node:path'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import { z } from 'zod'
import { detectPackageManager, runnerCommand } from '../commands/init/utils.js'
import {
  type ResolveDatabaseUrlOptions,
  withResolverContext,
} from './database-url.js'
import {
  missingCipherStashPackage,
  reportMissingCipherStashPackage,
} from './missing-package.js'

export interface StashConfig {
  /** PostgreSQL connection string */
  databaseUrl: string
  /** Path to encryption client file. Defaults to `'./src/encryption/index.ts'`. */
  client?: string
}

/** The config shape after Zod validation, with all defaults applied. */
export type ResolvedStashConfig = Required<Pick<StashConfig, 'client'>> &
  Omit<StashConfig, 'client'>

/**
 * Define a stash config with type checking.
 * Use this as the default export in your `stash.config.ts`.
 *
 * @example
 * ```ts
 * import { defineConfig } from 'stash'
 *
 * export default defineConfig({
 *   databaseUrl: process.env.DATABASE_URL!,
 *   client: './src/encryption/index.ts',
 * })
 * ```
 */
export function defineConfig(config: StashConfig): StashConfig {
  return config
}

const CONFIG_FILENAME = 'stash.config.ts'

/**
 * Default encryption-client path — the single source of truth for the location
 * a scaffolded config points at and the Zod default when `client` is omitted.
 * Imported by the scaffolder and the init schema builder so they can't drift.
 */
export const DEFAULT_CLIENT_PATH = './src/encryption/index.ts'

const stashConfigSchema = z.object({
  databaseUrl: z
    .string({ required_error: 'databaseUrl is required' })
    .min(1, 'databaseUrl must not be empty'),
  client: z.string().default(DEFAULT_CLIENT_PATH),
})

/**
 * Search for `stash.config.ts` starting from `startDir` and walking up
 * parent directories until the filesystem root is reached.
 *
 * Returns the absolute path if found, or `undefined` if not. Exported so
 * commands can branch on whether a config is present without loading it (e.g.
 * `eql install` resolves the database URL directly when there's no config).
 */
export function findConfigFile(startDir: string): string | undefined {
  let dir = path.resolve(startDir)

  while (true) {
    const candidate = path.join(dir, CONFIG_FILENAME)

    if (fs.existsSync(candidate)) {
      return candidate
    }

    const parent = path.dirname(dir)

    // Reached filesystem root
    if (parent === dir) {
      return undefined
    }

    dir = parent
  }
}

/**
 * Load and validate the `stash.config.ts` from the user's project.
 *
 * Searches from `process.cwd()` upward. Uses `jiti` to evaluate the
 * TypeScript config file at runtime without a separate compile step.
 *
 * The optional `resolverOptions` argument is threaded into an
 * `AsyncLocalStorage` scope around the jiti-import call, so that any
 * `await resolveDatabaseUrl()` inside the user's config file picks up
 * `--database-url` / `--supabase` flag values from the surrounding CLI
 * command. This is how the CLI passes flag context into config
 * evaluation without mutating `process.env` or relying on globals.
 *
 * `knownConfigPath` lets a caller that already located the config (via
 * {@link findConfigFile}) skip a second cwd→root filesystem walk.
 *
 * Exits with code 1 if the config file is not found or fails validation.
 */
export async function loadStashConfig(
  resolverOptions: ResolveDatabaseUrlOptions = {},
  knownConfigPath?: string,
): Promise<ResolvedStashConfig> {
  const configPath = knownConfigPath ?? findConfigFile(process.cwd())

  if (!configPath) {
    const stash = runnerCommand(detectPackageManager(), 'stash')
    console.error(`Error: Could not find ${CONFIG_FILENAME}

Run \`${stash} init\` to set up CipherStash (recommended), or
\`${stash} eql install\` to scaffold a ${CONFIG_FILENAME} and install EQL.

To create it by hand, add ${CONFIG_FILENAME} to your project root:

  import { defineConfig, resolveDatabaseUrl } from 'stash'

  export default defineConfig({
    databaseUrl: await resolveDatabaseUrl(),
  })
`)
    process.exit(1)
  }

  const { createJiti } = await import('jiti')
  const jiti = createJiti(configPath)

  let rawConfig: unknown
  try {
    // The per-call `{ default: true }` option is the jiti 2.x way to ask
    // for the default export to be unwrapped. The `interopDefault`
    // *constructor* option only applies to the deprecated synchronous
    // `jiti(id)` callable form — `jiti.import()` silently ignores it and
    // returns the full module namespace (`{ default: { ... } }`). That
    // wrapper would then fail Zod validation with a misleading
    // "databaseUrl: received undefined" even when the user's config sets
    // it (#374).
    rawConfig = await withResolverContext(resolverOptions, () =>
      jiti.import(configPath, { default: true }),
    )
  } catch (error) {
    // A missing CipherStash package (the config `import`s `stash`) is the common
    // standalone-npx failure — translate jiti's raw `Cannot find module 'stash'`
    // into actionable guidance instead of a stack trace (#579).
    const missingPkg = missingCipherStashPackage(error)
    if (missingPkg) reportMissingCipherStashPackage(missingPkg)
    console.error(`Error: Failed to load ${CONFIG_FILENAME} at ${configPath}\n`)
    console.error(error)
    process.exit(1)
  }

  const result = stashConfigSchema.safeParse(rawConfig)

  if (!result.success) {
    console.error(`Error: Invalid ${CONFIG_FILENAME}\n`)

    for (const issue of result.error.issues) {
      console.error(`  - ${issue.path.join('.')}: ${issue.message}`)
    }

    console.error()
    process.exit(1)
  }

  return result.data
}

/**
 * Load the encryption schema file referenced by the stash config.
 *
 * Resolves the schema path relative to `process.cwd()`, loads the file via
 * `jiti`, collects all exported `EncryptedTable` instances, and builds the
 * encrypt config via `buildEncryptConfig`.
 *
 * Exits with code 1 if the file cannot be loaded or contains no tables.
 */
export async function loadEncryptConfig(
  encryptClientPath: string,
): Promise<EncryptConfig | undefined> {
  const encryptClient = await loadEncryptionClient(encryptClientPath)

  return requireUsableEncryptConfig(
    encryptClient.getEncryptConfig(),
    encryptClientPath,
  )
}

/**
 * Find the user's `EncryptionClient` in their encryption-client file.
 *
 * Extracted from {@link loadEncryptConfig} so that {@link loadEncryptSchemas}
 * reaches the same export through the same jiti load and the same refusals —
 * two loaders that hand-copied this is exactly how the placeholder guard
 * drifted before (see {@link requireUsableEncryptConfig}).
 *
 * Exits with code 1 if the file is missing, fails to load, or exports no
 * client.
 */
async function loadEncryptionClient(
  encryptClientPath: string,
): Promise<EncryptionClient> {
  const resolvedPath = path.resolve(process.cwd(), encryptClientPath)

  if (!fs.existsSync(resolvedPath)) {
    console.error(
      `Error: Encrypt client file not found at ${resolvedPath}\n\nCheck the "encryptClient" path in your ${CONFIG_FILENAME}.`,
    )
    process.exit(1)
  }

  const { createJiti } = await import('jiti')
  const jiti = createJiti(resolvedPath)

  let moduleExports: Record<string, unknown>
  try {
    // No `{ default: true }` here — we want the full module namespace so
    // `Object.values` can find an EncryptionClient regardless of whether
    // the user re-exports it as `default` or as a named binding.
    moduleExports = (await jiti.import(resolvedPath)) as Record<string, unknown>
  } catch (error) {
    // The client `import`s `@cipherstash/stack` (incl. subpaths). If that isn't
    // installed, translate the raw jiti stack trace into the same actionable
    // guidance the config load gives, rather than leaking it (#579 / review #3).
    const missingPkg = missingCipherStashPackage(error)
    if (missingPkg) reportMissingCipherStashPackage(missingPkg)
    console.error(
      `Error: Failed to load encrypt client file at ${resolvedPath}\n`,
    )
    console.error(error)
    process.exit(1)
  }

  const encryptClient = Object.values(moduleExports).find(
    (value): value is EncryptionClient =>
      !!value &&
      typeof value === 'object' &&
      'getEncryptConfig' in value &&
      typeof (value as { getEncryptConfig?: unknown }).getEncryptConfig ===
        'function',
  )

  if (!encryptClient) {
    console.error(
      `Error: No EncryptionClient export found in ${encryptClientPath}.`,
    )
    process.exit(1)
  }

  return encryptClient
}

/** What {@link loadEncryptSchemas} recovers from the user's client file. */
export interface LoadedEncryptSchemas {
  /** The built encrypt config — always present, same value `loadEncryptConfig` returns. */
  config: EncryptConfig
  /**
   * The declared v3 tables, when the installed `@cipherstash/stack` exposes
   * `getSchemas()`. `undefined` on an older release, which is why every caller
   * has to degrade rather than assume.
   */
  schemas: readonly AnyV3Table[] | undefined
}

/**
 * Load the user's encryption client and recover BOTH views of its schema: the
 * built `EncryptConfig` and — when available — the declared v3 tables.
 *
 * The two are not interchangeable. `EncryptedV3Column.build()` emits only
 * `{ cast_as, indexes }`, so the concrete domain name never reaches the encrypt
 * config: `cast_as: 'number'` with an `ope` index is ambiguous across
 * `eql_v3_integer_ord`, `smallint_ord`, `real_ord`, `double_ord` and
 * `numeric_ord`. Any rule that reasons about the DECLARED domain — steering
 * `_ord_ore` columns, or drift-checking against a live database's
 * `information_schema.columns.domain_name` — needs the tables themselves.
 *
 * `schemas` is `undefined` when the project's installed `@cipherstash/stack`
 * predates `getSchemas()`. That is a real customer state (the CLI and the
 * library version independently), so it degrades to config-only rather than
 * failing: the caller runs the subset of rules the encrypt config can answer
 * and says which ones it skipped.
 *
 * Exits with code 1 through the same refusals as {@link loadEncryptConfig}.
 */
export async function loadEncryptSchemas(
  encryptClientPath: string,
): Promise<LoadedEncryptSchemas> {
  const encryptClient = await loadEncryptionClient(encryptClientPath)

  const config = requireUsableEncryptConfig(
    encryptClient.getEncryptConfig(),
    encryptClientPath,
  )

  // Duck-typed, not a version check: the client comes from the USER's
  // node_modules via jiti, so its shape is the only reliable signal of what it
  // supports.
  const getSchemas = (
    encryptClient as { getSchemas?: () => readonly AnyV3Table[] }
  ).getSchemas

  if (typeof getSchemas !== 'function') {
    return { config, schemas: undefined }
  }

  const schemas = getSchemas.call(encryptClient)

  // A client built by an adapter (or a hand-rolled stub) could return
  // something other than an array of tables. Verify the shape rather than
  // trusting it — the caller's rules dereference `columnBuilders`.
  if (!Array.isArray(schemas) || !schemas.every(isV3TableLike)) {
    return { config, schemas: undefined }
  }

  return { config, schemas }
}

/**
 * Structural check for the parts of an `EncryptedTable` the schema rules read.
 *
 * Checks the BUILDERS too, not just the map that holds them. The rules call
 * `build()`, `getName()`, `getEqlType()` and `isQueryable()` on every one, so a
 * table carrying inert objects is as unusable as a missing map — and
 * `typeof null === 'object'`, so a null `columnBuilders` would otherwise pass
 * here and reach `Object.values(null)`, turning a degradable client into a
 * stack trace.
 */
function isV3TableLike(value: unknown): value is AnyV3Table {
  if (!value || typeof value !== 'object') return false

  const { tableName, columnBuilders } = value as {
    tableName?: unknown
    columnBuilders?: unknown
  }

  if (typeof tableName !== 'string') return false
  if (!columnBuilders || typeof columnBuilders !== 'object') return false

  return Object.values(columnBuilders).every(isV3ColumnLike)
}

/** The column-builder methods `collectDeclaredColumns` calls on every column. */
function isV3ColumnLike(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false

  const builder = value as Record<string, unknown>

  return (['build', 'getName', 'getEqlType', 'isQueryable'] as const).every(
    (method) => typeof builder[method] === 'function',
  )
}

/**
 * Refuse an encryption client that cannot drive any command yet, naming the
 * cause.
 *
 * Shared rather than duplicated because it guards ONE file reached by two
 * loaders — `loadEncryptConfig` for `stash eql validate`, and
 * `loadEncryptionContext` for `stash encrypt backfill`. When the copies were
 * separate they had already drifted on the nullish-config case, so one command
 * named the cause while the other fell through to `requireTable`'s `Table
 * "users" was not found … Available: (none)` — the symptom-not-cause message
 * this guard exists to replace (#787 review follow-up).
 *
 * Both refusals are hard exits: there is no partially-usable state here, and
 * every caller would otherwise have to re-derive that.
 *
 * `sourceLabel` names where the config came from. It defaults to the
 * client-file phrasing, but not every caller loads a client file: the Prisma
 * Next pass derives the schemas from an emitted `contract.json`, where
 * "Encryption client in …/contract.json" would send the user looking for a
 * file they are not supposed to author (#819 review).
 */
export function requireUsableEncryptConfig(
  config: EncryptConfig | undefined,
  encryptClientPath: string,
  sourceLabel = `Encryption client in ${encryptClientPath}`,
): EncryptConfig {
  if (!config) {
    console.error(`Error: ${sourceLabel} has no initialized encrypt config.`)
    process.exit(1)
  }

  // `stash init` scaffolds a client holding one placeholder table, because
  // `Encryption` requires a non-empty schema set and the scaffold has no real
  // tables to name yet. Reaching here with only that table means the user never
  // replaced it.
  //
  // Read from the built encrypt config, never from the module's export map: a
  // scaffold whose `export` keyword was dropped is still un-replaced, while a
  // stale `export const placeholderTable` beside real tables that are imported
  // rather than re-exported is not (#787 review).
  const tables = Object.keys(config.tables ?? {})
  if (tables.length === 1 && tables[0] === PLACEHOLDER_TABLE_NAME) {
    console.error(
      `Error: ${sourceLabel} still contains the placeholder table \`${PLACEHOLDER_TABLE_NAME}\` that \`stash init\` wrote.\n\nDeclare your encrypted columns and pass those tables to Encryption({ schemas: [...] }) in that file, then re-run this command.`,
    )
    process.exit(1)
  }

  return config
}

/**
 * The table name `stash init`'s scaffold uses so the file it writes compiles.
 *
 * Kept in sync with the templates in `commands/init/utils.ts` by
 * `__tests__/placeholder-client-fixture.test.ts`, which also typechecks them.
 */
export const PLACEHOLDER_TABLE_NAME = '__stash_placeholder__'
