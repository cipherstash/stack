import fs from 'node:fs'
import path from 'node:path'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
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

  const config = encryptClient.getEncryptConfig()
  if (!config) {
    console.error(
      `Error: Encryption client in ${encryptClientPath} has no initialized encrypt config.`,
    )
    process.exit(1)
  }
  return config
}
