import fs from 'node:fs'
import path from 'node:path'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import { z } from 'zod'
import {
  combinedInstallCommands,
  detectPackageManager,
  runnerCommand,
} from '../commands/init/utils.js'
import {
  type ResolveDatabaseUrlOptions,
  withResolverContext,
} from './database-url.js'

/** The npm packages a `stash.config.ts` (and the client it points at) import. */
const CLI_PACKAGE = 'stash'
const STACK_PACKAGE = '@cipherstash/stack'

/**
 * When jiti fails to evaluate the config because a required CipherStash package
 * isn't installed in the project, Node throws a `MODULE_NOT_FOUND` /
 * `ERR_MODULE_NOT_FOUND`. Return the offending package name so the caller can
 * print actionable guidance instead of a raw stack trace; return `undefined`
 * for any other failure (which should surface as-is).
 *
 * This is the standalone `npx stash eql install` failure mode: the scaffolded
 * config `import`s `stash`, which resolves only when the CLI packages were added
 * as project dependencies (via `stash init`) — see #579.
 */
function missingConfigModule(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined
  const code = (error as { code?: string }).code
  if (code !== 'MODULE_NOT_FOUND' && code !== 'ERR_MODULE_NOT_FOUND') {
    return undefined
  }
  // Check the scoped package first — `stash` is a substring of paths that
  // mention it, but the quoted `'@cipherstash/stack'` is the specific specifier.
  for (const pkg of [STACK_PACKAGE, CLI_PACKAGE]) {
    if (
      error.message.includes(`'${pkg}'`) ||
      error.message.includes(`"${pkg}"`)
    ) {
      return pkg
    }
  }
  return undefined
}

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

const DEFAULT_ENCRYPT_CLIENT_PATH = './src/encryption/index.ts'

const stashConfigSchema = z.object({
  databaseUrl: z
    .string({ required_error: 'databaseUrl is required' })
    .min(1, 'databaseUrl must not be empty'),
  client: z.string().default(DEFAULT_ENCRYPT_CLIENT_PATH),
})

/**
 * Search for `stash.config.ts` starting from `startDir` and walking up
 * parent directories until the filesystem root is reached.
 *
 * Returns the absolute path if found, or `undefined` if not.
 */
function findConfigFile(startDir: string): string | undefined {
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
 * Exits with code 1 if the config file is not found or fails validation.
 */
export async function loadStashConfig(
  resolverOptions: ResolveDatabaseUrlOptions = {},
): Promise<ResolvedStashConfig> {
  const configPath = findConfigFile(process.cwd())

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
    // A missing CipherStash package (the config `import`s `stash`; the client it
    // points at `import`s `@cipherstash/stack`) is the common standalone-npx
    // failure — translate jiti's raw `Cannot find module 'stash'` into
    // actionable guidance instead of a stack trace (#579).
    const missingPkg = missingConfigModule(error)
    if (missingPkg) {
      const pm = detectPackageManager()
      const stash = runnerCommand(pm, 'stash')
      const install = combinedInstallCommands(
        pm,
        [STACK_PACKAGE],
        [CLI_PACKAGE],
      )
      console.error(
        `Error: ${CONFIG_FILENAME} could not load — \`${missingPkg}\` is not installed in this project.

Install the CipherStash packages, then re-run:
  ${install.join('\n  ')}

Or run \`${stash} init\` to set everything up.
`,
      )
      process.exit(1)
    }
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
