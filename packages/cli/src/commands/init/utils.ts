import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import type { Integration, SchemaDef } from './types.js'

/**
 * Checks if a package is installed and loadable from the current project.
 *
 * We require both the package directory AND a `package.json` inside it. A
 * leftover directory without a manifest (from an aborted install, a previous
 * tool that wrote the path before failing, or a workspace symlink whose
 * target was removed) was previously treated as installed — that caused
 * `installCommand` later in init to load `stash.config.ts` and fail with
 * `Cannot find module 'stash'` at the jiti import. Requiring the manifest
 * matches what Node's resolver actually needs to load the module.
 */
export function isPackageInstalled(packageName: string): boolean {
  const modulePath = resolve(process.cwd(), 'node_modules', packageName)
  const manifestPath = resolve(modulePath, 'package.json')
  return existsSync(modulePath) && existsSync(manifestPath)
}

/**
 * The RESOLVED version of an installed package — what's actually on disk in
 * `node_modules/<pkg>/package.json`, not the specifier in the project
 * manifest. Used by init to detect version skew against the release this CLI
 * shipped with (#661): a stale or placeholder install (`0.19.0` / `0.0.0`
 * from a lagging dist-tag) hides behind a `^`-range spec but is obvious here.
 * Returns `undefined` when the package (or its manifest version) is absent.
 */
export function installedVersion(packageName: string): string | undefined {
  const manifestPath = resolve(
    process.cwd(),
    'node_modules',
    packageName,
    'package.json',
  )
  if (!existsSync(manifestPath)) return undefined
  try {
    const manifest: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'))
    const version = (manifest as { version?: unknown }).version
    return typeof version === 'string' && version.length > 0
      ? version
      : undefined
  } catch {
    return undefined
  }
}

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun'

/**
 * Parse `npm_config_user_agent` to identify a non-npm runner.
 *
 * npm, pnpm, yarn, and bun all set this env var when they invoke a package
 * script or a `*x`/`dlx`-style runner. It starts with `"<tool>/<version> ..."`.
 *
 * We only trust non-npm values. `bunx`, `pnpm dlx`, and `yarn dlx` are
 * deliberate choices by the user. `npm`/`npx` is the default and often a
 * reflex invocation, so we don't let it override lockfile detection.
 */
function packageManagerFromUserAgent(): PackageManager | undefined {
  const ua = process.env.npm_config_user_agent
  if (!ua) return undefined
  if (ua.startsWith('bun/')) return 'bun'
  if (ua.startsWith('pnpm/')) return 'pnpm'
  if (ua.startsWith('yarn/')) return 'yarn'
  return undefined
}

/**
 * Detect the package manager used for the current project.
 *
 * Priority:
 *  1. `npm_config_user_agent` — when the user explicitly invokes via
 *     `bunx`/`pnpm dlx`/`yarn dlx`, honour that choice even in projects
 *     without a matching lockfile (e.g. fresh projects).
 *  2. Lockfile in cwd — respects the existing project convention.
 *  3. Default to `npm`.
 *
 * Cached per (cwd, user-agent) pair: the same CLI process never changes
 * either, but tests vary both via `vi.spyOn(process, 'cwd')` so the cache
 * has to be input-keyed rather than a single slot.
 */
const pmCache = new Map<string, PackageManager>()

export function detectPackageManager(): PackageManager {
  const cwd = process.cwd()
  const ua = process.env.npm_config_user_agent ?? ''
  const cacheKey = `${cwd}\n${ua}`
  const cached = pmCache.get(cacheKey)
  if (cached) return cached

  const fromUserAgent = packageManagerFromUserAgent()
  if (fromUserAgent) {
    pmCache.set(cacheKey, fromUserAgent)
    return fromUserAgent
  }

  let pm: PackageManager = 'npm'
  if (
    existsSync(resolve(cwd, 'bun.lockb')) ||
    existsSync(resolve(cwd, 'bun.lock'))
  ) {
    pm = 'bun'
  } else if (existsSync(resolve(cwd, 'pnpm-lock.yaml'))) {
    pm = 'pnpm'
  } else if (existsSync(resolve(cwd, 'yarn.lock'))) {
    pm = 'yarn'
  }
  pmCache.set(cacheKey, pm)
  return pm
}

/** Returns the install command for adding a production dependency with the given package manager. */
export function prodInstallCommand(
  pm: ReturnType<typeof detectPackageManager>,
  packageName: string,
): string {
  switch (pm) {
    case 'bun':
      return `bun add ${packageName}`
    case 'pnpm':
      return `pnpm add ${packageName}`
    case 'yarn':
      return `yarn add ${packageName}`
    case 'npm':
      return `npm install ${packageName}`
  }
}

/** Returns the install command for adding a dev dependency with the given package manager. */
export function devInstallCommand(
  pm: ReturnType<typeof detectPackageManager>,
  packageName: string,
): string {
  switch (pm) {
    case 'bun':
      return `bun add -D ${packageName}`
    case 'pnpm':
      return `pnpm add -D ${packageName}`
    case 'yarn':
      return `yarn add -D ${packageName}`
    case 'npm':
      return `npm install -D ${packageName}`
  }
}

/**
 * Build the install command(s) that add multiple dependencies at once.
 * npm/pnpm/yarn/bun all accept a space-separated package list, so we
 * use the existing `prodInstallCommand` / `devInstallCommand` builders
 * with a joined argument. Returns one or two strings depending on
 * whether prod and dev lists are both non-empty.
 */
export function combinedInstallCommands(
  pm: PackageManager,
  prodPackages: string[],
  devPackages: string[],
): string[] {
  const commands: string[] = []
  if (prodPackages.length > 0) {
    commands.push(prodInstallCommand(pm, prodPackages.join(' ')))
  }
  if (devPackages.length > 0) {
    commands.push(devInstallCommand(pm, devPackages.join(' ')))
  }
  return commands
}

/**
 * Returns the one-shot remote-execution command for the given package
 * manager, ready to prefix a package reference. We mirror what each tool
 * documents:
 *   npm  → `npx`
 *   bun  → `bunx`
 *   pnpm → `pnpm dlx`
 *   yarn → `yarn dlx`
 *
 * `ref` is appended verbatim, so callers may pass `'stash'` or
 * `'stash eql install'`.
 */
export function runnerCommand(pm: PackageManager, ref: string): string {
  switch (pm) {
    case 'bun':
      return `bunx ${ref}`
    case 'pnpm':
      return `pnpm dlx ${ref}`
    case 'yarn':
      return `yarn dlx ${ref}`
    case 'npm':
      return `npx ${ref}`
  }
}

/**
 * argv split of {@link runnerCommand} for callers using `spawnSync` /
 * `spawn` rather than a shell. Returns the binary plus any prefix args
 * (`pnpm dlx` / `yarn dlx`); the caller appends the remaining argv.
 */
export function runnerArgv(pm: PackageManager): {
  command: string
  prefixArgs: string[]
} {
  switch (pm) {
    case 'bun':
      return { command: 'bunx', prefixArgs: [] }
    case 'pnpm':
      return { command: 'pnpm', prefixArgs: ['dlx'] }
    case 'yarn':
      return { command: 'yarn', prefixArgs: ['dlx'] }
    case 'npm':
      return { command: 'npx', prefixArgs: [] }
  }
}

/**
 * Map the package manager to the right "run a binary from node_modules" form —
 * distinct from {@link runnerCommand}, which is the download-and-run
 * (`pnpm dlx` / `npx <pkg>`) form. For a project-local binary like drizzle-kit
 * you want the local one, so it resolves the project's own install and its
 * `drizzle.config.ts` / schema imports rather than fetching a fresh copy into a
 * temp store.
 *   npm  → `npx --no-install` (never surprise-download a dep that should exist)
 *   pnpm → `pnpm exec`
 *   yarn → `yarn` (works for yarn 1 and berry: `yarn <bin>`)
 *   bun  → `bun x --no-install` (binary-runner mode, not the `bunx` dlx alias;
 *          `--no-install` keeps it from auto-fetching a missing binary from npm)
 */
export function execCommand(pm: PackageManager): string {
  switch (pm) {
    case 'npm':
      return 'npx --no-install'
    case 'pnpm':
      return 'pnpm exec'
    case 'yarn':
      return 'yarn'
    case 'bun':
      return 'bun x --no-install'
  }
}

/**
 * argv split of {@link execCommand} for callers using `spawnSync` / `spawn`
 * (no shell → no word-splitting or injection from interpolated arguments).
 * Returns the binary plus any prefix args; the caller appends the rest.
 */
export function execArgv(pm: PackageManager): {
  command: string
  prefixArgs: string[]
} {
  switch (pm) {
    case 'npm':
      return { command: 'npx', prefixArgs: ['--no-install'] }
    case 'pnpm':
      return { command: 'pnpm', prefixArgs: ['exec'] }
    case 'yarn':
      return { command: 'yarn', prefixArgs: [] }
    case 'bun':
      return { command: 'bun', prefixArgs: ['x', '--no-install'] }
  }
}

function toCamelCase(str: string): string {
  return str.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
}

function generateDrizzleFromSchemas(schemas: SchemaDef[]): string {
  const tableDefs = schemas.map((schema) => {
    const varName = `${toCamelCase(schema.tableName)}Table`
    const schemaVarName = `${toCamelCase(schema.tableName)}Schema`

    const columnDefs = schema.columns.map(
      (col) => `  ${col.name}: types.${col.domain}('${col.name}'),`,
    )

    return `export const ${varName} = pgTable('${schema.tableName}', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
${columnDefs.join('\n')}
  createdAt: timestamp('created_at').defaultNow(),
})

const ${schemaVarName} = extractEncryptionSchema(${varName})`
  })

  const schemaVarNames = schemas.map((s) => `${toCamelCase(s.tableName)}Schema`)

  return `import { pgTable, integer, timestamp } from 'drizzle-orm/pg-core'
import { types, extractEncryptionSchema } from '@cipherstash/stack-drizzle'
import { Encryption } from '@cipherstash/stack/v3'

${tableDefs.join('\n\n')}

export const encryptionClient = await Encryption({
  schemas: [${schemaVarNames.join(', ')}],
})
`
}

function generateGenericFromSchemas(schemas: SchemaDef[]): string {
  const tableDefs = schemas.map((schema) => {
    const varName = `${toCamelCase(schema.tableName)}Table`

    const columnDefs = schema.columns.map(
      (col) => `  ${col.name}: types.${col.domain}('${col.name}'),`,
    )

    return `export const ${varName} = encryptedTable('${schema.tableName}', {
${columnDefs.join('\n')}
})`
  })

  const tableVarNames = schemas.map((s) => `${toCamelCase(s.tableName)}Table`)

  return `import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'

${tableDefs.join('\n\n')}

export const encryptionClient = await Encryption({
  schemas: [${tableVarNames.join(', ')}],
})
`
}

/**
 * Generate the encryption client file contents for one or more schemas.
 *
 * The single-schema variants above are kept for the placeholder path (which
 * is always exactly one table); this is the variant that renders a real
 * multi-table client from DB introspection.
 */
export function generateClientFromSchemas(
  integration: Integration,
  schemas: SchemaDef[],
): string {
  switch (integration) {
    case 'drizzle':
      return generateDrizzleFromSchemas(schemas)
    case 'supabase':
    case 'postgresql':
      return generateGenericFromSchemas(schemas)
    case 'prisma-next':
      // `schema build` doesn't scaffold a prisma-next client — that integration
      // uses its own per-domain constructors (`cipherstash.TextSearch()` …) and
      // a migration-based flow, not the `types.*` client this emits. It never
      // reaches here (schema/build.ts only produces 'supabase' | 'postgresql'),
      // but fail loudly rather than writing an `undefined` client if it ever
      // does. Naming every case also keeps the switch exhaustive, so a new
      // Integration can't silently fall through to `undefined` again.
      throw new Error(
        '`stash schema build` does not generate a prisma-next client; use `stash plan` → `stash impl` instead.',
      )
  }
}

/**
 * Generate the placeholder encryption-client file `stash init` writes.
 *
 * Deliberately *not* a fully-formed schema: we used to introspect the user's
 * DB and synthesise a `pgTable` here, which left users with two parallel
 * definitions (the real one in `src/db/schema.ts` and the synthesised one
 * here) and no clear way to reconcile them. The agent at handoff time was
 * left guessing which was canonical.
 *
 * The placeholder now shows the encryption-client patterns inline as
 * commented examples, exports a `encryptionClient` that points at no
 * schemas yet, and explicitly tells the agent that the user's existing
 * schema files remain authoritative. The agent's job during the handoff
 * is to declare encrypted columns directly in those files and update the
 * `Encryption({ schemas: [...] })` call below to reference them.
 */
export function generatePlaceholderClient(integration: Integration): string {
  if (integration === 'drizzle') {
    return DRIZZLE_PLACEHOLDER
  }
  return GENERIC_PLACEHOLDER
}

const DRIZZLE_PLACEHOLDER = `/**
 * CipherStash encryption client — placeholder.
 *
 * \`stash init\` wrote this file. It is intentionally NOT a real Drizzle
 * schema. Your existing schema files (typically under \`src/db/\`) remain
 * authoritative — your agent will edit those directly when you encrypt a
 * column, then update the \`Encryption({ schemas: [...] })\` call below
 * to reference the encrypted tables you declared there.
 *
 * Until that happens, the encryption client is initialised with no
 * schemas, and \`stash encrypt\` commands will surface a clear error
 * pointing at this file.
 *
 * This project uses EQL v3. Encrypted columns are concrete Postgres domains
 * built with the \`types.*\` factories from \`@cipherstash/stack-drizzle\`.
 * Each domain's query capabilities are FIXED by the type you pick — there is
 * no capability config object. Choose the factory whose capabilities you need:
 *   types.Text / types.Integer / …     storage only (encrypt/decrypt, no queries)
 *   types.TextEq / types.IntegerEq     equality (eq, inArray)
 *   types.IntegerOrd / types.DateOrd   equality + order/range (gt/lt/between/sort)
 *   types.TextMatch                    free-text match only
 *   types.TextSearch                   equality + order/range + free-text
 *   types.Json                         encrypted-JSONB containment + selectors
 *
 * --- Pattern reference (copy into your real schema, do NOT use as-is) ---
 *
 * Encrypted twin column for an existing populated column (path 3 — lifecycle):
 *
 *   import { pgTable, integer, text } from 'drizzle-orm/pg-core'
 *   import { types } from '@cipherstash/stack-drizzle'
 *
 *   export const users = pgTable('users', {
 *     id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
 *     email: text('email').notNull(),                        // existing plaintext, unchanged for now
 *     email_encrypted: types.TextSearch('email_encrypted'),  // encrypted twin, NULLABLE — never .notNull()
 *   })
 *
 * Net-new encrypted column (path 1 — declare encrypted from the start):
 *
 *   export const orders = pgTable('orders', {
 *     id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
 *     billing_address: types.TextEq('billing_address'),
 *   })
 *
 * Once you have encrypted tables declared, harvest them and pass to Encryption():
 *
 *   import { extractEncryptionSchema } from '@cipherstash/stack-drizzle'
 *   import { Encryption } from '@cipherstash/stack/v3'
 *   import { users, orders } from './db/schema'
 *
 *   export const encryptionClient = await Encryption({
 *     schemas: [extractEncryptionSchema(users), extractEncryptionSchema(orders)],
 *   })
 */
import { Encryption } from '@cipherstash/stack/v3'

export const encryptionClient = await Encryption({ schemas: [] })
`

const GENERIC_PLACEHOLDER = `/**
 * CipherStash encryption client — placeholder.
 *
 * \`stash init\` wrote this file. It is intentionally NOT a real schema
 * definition. Your existing schema files remain authoritative — your
 * agent will declare encrypted columns there and update the
 * \`Encryption({ schemas: [...] })\` call below to reference them.
 *
 * Until that happens, the encryption client is initialised with no
 * schemas, and \`stash encrypt\` commands will surface a clear error
 * pointing at this file.
 *
 * This project uses EQL v3. Encrypted columns are concrete Postgres domains
 * built with the \`types.*\` factories from \`@cipherstash/stack/eql/v3\`
 * (also re-exported from \`@cipherstash/stack/v3\`). Each domain's query
 * capabilities are FIXED by the type you pick — there is no chainable
 * capability tuner. Choose the factory whose capabilities you need:
 *   types.Text / types.Integer / …     storage only (encrypt/decrypt, no queries)
 *   types.TextEq / types.IntegerEq     equality
 *   types.IntegerOrd / types.DateOrd   equality + order/range
 *   types.TextMatch                    free-text match only
 *   types.TextSearch                   equality + order/range + free-text
 *   types.Json                         encrypted-JSONB containment + selectors
 *
 * --- Pattern reference (copy into your real schema, do NOT use as-is) ---
 *
 * Encrypted twin column for an existing populated column (path 3 — lifecycle):
 *
 *   import { encryptedTable, types } from '@cipherstash/stack/v3'
 *
 *   export const users = encryptedTable('users', {
 *     email_encrypted: types.TextSearch('email_encrypted'),
 *   })
 *
 * Net-new encrypted column (path 1 — declare encrypted from the start):
 *
 *   export const orders = encryptedTable('orders', {
 *     billing_address: types.TextEq('billing_address'),
 *   })
 *
 * Once you have encrypted tables declared, pass them to Encryption():
 *
 *   import { Encryption } from '@cipherstash/stack/v3'
 *   import { users, orders } from './db/schema'
 *
 *   export const encryptionClient = await Encryption({
 *     schemas: [users, orders],
 *   })
 */
import { Encryption } from '@cipherstash/stack/v3'

export const encryptionClient = await Encryption({ schemas: [] })
`
