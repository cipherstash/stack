import { config } from 'dotenv'

// Load env files in Next.js precedence order. dotenv's default behavior is to
// not overwrite vars that are already set, so loading .env.local first means
// its values win over .env for the same keys. Users can still set anything in
// the real environment to override both.
config({ path: '.env.local' })
config({ path: '.env.development.local' })
config({ path: '.env.development' })
config({ path: '.env' })

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as p from '@clack/prompts'
// Commands that depend on @cipherstash/stack are lazy-loaded in the switch below.
import {
  authCommand,
  envCommand,
  initCommand,
  installCommand,
  statusCommand,
  testConnectionCommand,
  upgradeCommand,
} from '../commands/index.js'

function isModuleNotFound(err: unknown): boolean {
  return (
    err instanceof Error &&
    'code' in err &&
    (err as { code: string }).code === 'ERR_MODULE_NOT_FOUND'
  )
}

async function requireStack<T>(importFn: () => Promise<T>): Promise<T> {
  try {
    return await importFn()
  } catch (err: unknown) {
    if (isModuleNotFound(err)) {
      p.log.error(
        '@cipherstash/stack is required for this command.\n' +
          '  Install it with: npm install @cipherstash/stack\n' +
          '  Or run: npx @cipherstash/cli init',
      )
      process.exit(1) as never
    }
    throw err
  }
}

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf-8'),
)

const HELP = `
CipherStash CLI v${pkg.version}

Usage: npx @cipherstash/cli <command> [options]

Commands:
  init                 Initialize CipherStash for your project
  auth <subcommand>    Authenticate with CipherStash
  wizard               AI-powered encryption setup (reads your codebase)

  db install           Scaffold stash.config.ts (if missing) and install EQL extensions
  db upgrade           Upgrade EQL extensions to the latest version
  db push              Push encryption schema to database (CipherStash Proxy only)
  db validate          Validate encryption schema
  db migrate           Run pending encrypt config migrations
  db status            Show EQL installation status
  db test-connection   Test database connectivity

  schema build         Build an encryption schema from your database

  encrypt status       Show per-column migration status (phase, progress, drift)
  encrypt plan         Diff intent (.cipherstash/migrations.json) vs observed state
  encrypt advance      Record a phase transition for a column
  encrypt backfill     Resumably encrypt plaintext into the encrypted column
  encrypt cutover      Rename swap encrypted → primary column
  encrypt drop         Generate a migration to drop the plaintext column

  env                  (experimental) Print production env vars for deployment

Options:
  --help, -h           Show help
  --version, -v        Show version

Init Flags:
  --supabase           Use Supabase-specific setup flow
  --drizzle            Use Drizzle-specific setup flow

DB Flags:
  --force                    (install) Reinstall / overwrite even if already installed
  --dry-run                  (install, push, upgrade) Show what would happen without making changes
  --supabase                 (install, upgrade, validate) Use Supabase-compatible mode (auto-detected from DATABASE_URL)
  --drizzle                  (install) Generate a Drizzle migration instead of direct install (auto-detected from project)
  --migration                (install, requires --supabase) Write a Supabase migration file instead of running SQL directly
  --direct                   (install, requires --supabase) Run the SQL directly against the database (mutually exclusive with --migration)
  --migrations-dir <path>    (install, requires --supabase) Override the Supabase migrations directory (default: supabase/migrations)
  --exclude-operator-family  (install, upgrade, validate) Skip operator family creation
  --latest                   (install, upgrade) Fetch the latest EQL from GitHub

Examples:
  npx @cipherstash/cli init
  npx @cipherstash/cli init --supabase
  npx @cipherstash/cli auth login
  npx @cipherstash/cli wizard
  npx @cipherstash/cli db install
  npx @cipherstash/cli db push
  npx @cipherstash/cli schema build
`.trim()

interface ParsedArgs {
  command: string | undefined
  subcommand: string | undefined
  commandArgs: string[]
  flags: Record<string, boolean>
  values: Record<string, string>
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2)
  const command = args[0]
  const subcommand = args[1] && !args[1].startsWith('-') ? args[1] : undefined
  const rest = args.slice(subcommand ? 2 : 1)

  const flags: Record<string, boolean> = {}
  const values: Record<string, string> = {}
  const commandArgs: string[] = []

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]
    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      const nextArg = rest[i + 1]
      if (nextArg !== undefined && !nextArg.startsWith('-')) {
        values[key] = nextArg
        i++
      } else {
        flags[key] = true
      }
    } else {
      commandArgs.push(arg)
    }
  }

  return { command, subcommand, commandArgs, flags, values }
}

async function runDbCommand(
  sub: string | undefined,
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
  switch (sub) {
    case 'install':
      await installCommand({
        force: flags.force,
        dryRun: flags['dry-run'],
        supabase: flags.supabase,
        excludeOperatorFamily: flags['exclude-operator-family'],
        drizzle: flags.drizzle,
        latest: flags.latest,
        name: values.name,
        out: values.out,
        migration: flags.migration,
        direct: flags.direct,
        migrationsDir: values['migrations-dir'],
      })
      break
    case 'upgrade':
      await upgradeCommand({
        dryRun: flags['dry-run'],
        supabase: flags.supabase,
        excludeOperatorFamily: flags['exclude-operator-family'],
        latest: flags.latest,
      })
      break
    case 'push': {
      const { pushCommand } = await requireStack(
        () => import('../commands/db/push.js'),
      )
      await pushCommand({ dryRun: flags['dry-run'] })
      break
    }
    case 'validate': {
      const { validateCommand } = await requireStack(
        () => import('../commands/db/validate.js'),
      )
      await validateCommand({
        supabase: flags.supabase,
        excludeOperatorFamily: flags['exclude-operator-family'],
      })
      break
    }
    case 'status':
      await statusCommand()
      break
    case 'test-connection':
      await testConnectionCommand()
      break
    case 'migrate':
      p.log.warn('"npx @cipherstash/cli db migrate" is not yet implemented.')
      break
    default:
      p.log.error(`Unknown db subcommand: ${sub ?? '(none)'}`)
      console.log()
      console.log(HELP)
      process.exit(1)
  }
}

async function runEncryptCommand(
  sub: string | undefined,
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
  switch (sub) {
    case 'status': {
      const { statusCommand } = await requireStack(
        () => import('../commands/encrypt/status.js'),
      )
      await statusCommand()
      break
    }
    case 'plan': {
      const { planCommand } = await requireStack(
        () => import('../commands/encrypt/plan.js'),
      )
      await planCommand()
      break
    }
    case 'advance': {
      const table = requireValue(values, 'table')
      const column = requireValue(values, 'column')
      const to = requireValue(values, 'to') as
        | 'schema-added'
        | 'dual-writing'
        | 'backfilling'
        | 'backfilled'
        | 'cut-over'
        | 'dropped'
      const { advanceCommand } = await requireStack(
        () => import('../commands/encrypt/advance.js'),
      )
      await advanceCommand({ table, column, to, note: values.note })
      break
    }
    case 'backfill': {
      const table = requireValue(values, 'table')
      const column = requireValue(values, 'column')
      const { backfillCommand } = await requireStack(
        () => import('../commands/encrypt/backfill.js'),
      )
      await backfillCommand({
        table,
        column,
        pkColumn: values['pk-column'],
        chunkSize: values['chunk-size']
          ? Number(values['chunk-size'])
          : undefined,
        encryptedColumn: values['encrypted-column'],
        schemaColumnKey: values['schema-column-key'],
      })
      break
    }
    case 'cutover': {
      const table = requireValue(values, 'table')
      const column = requireValue(values, 'column')
      const { cutoverCommand } = await requireStack(
        () => import('../commands/encrypt/cutover.js'),
      )
      await cutoverCommand({ table, column, proxyUrl: values['proxy-url'] })
      break
    }
    case 'drop': {
      const table = requireValue(values, 'table')
      const column = requireValue(values, 'column')
      const { dropCommand } = await requireStack(
        () => import('../commands/encrypt/drop.js'),
      )
      await dropCommand({
        table,
        column,
        migrationsDir: values['migrations-dir'],
      })
      break
    }
    default:
      p.log.error(`Unknown encrypt subcommand: ${sub ?? '(none)'}`)
      console.log()
      console.log(HELP)
      process.exit(1)
  }
}

function requireValue(values: Record<string, string>, key: string): string {
  const v = values[key]
  if (!v) {
    p.log.error(`Missing required --${key} value.`)
    process.exit(1)
  }
  return v
}

async function runSchemaCommand(
  sub: string | undefined,
  flags: Record<string, boolean>,
) {
  switch (sub) {
    case 'build': {
      const { builderCommand } = await requireStack(
        () => import('../commands/schema/build.js'),
      )
      await builderCommand({ supabase: flags.supabase })
      break
    }
    default:
      p.log.error(`Unknown schema subcommand: ${sub ?? '(none)'}`)
      console.log()
      console.log(HELP)
      process.exit(1)
  }
}

async function main() {
  const { command, subcommand, commandArgs, flags, values } = parseArgs(
    process.argv,
  )

  if (!command || command === '--help' || command === '-h' || flags.help) {
    console.log(HELP)
    return
  }

  if (command === '--version' || command === '-v' || flags.version) {
    console.log(pkg.version)
    return
  }

  switch (command) {
    case 'init':
      await initCommand(flags)
      break
    case 'auth': {
      const authArgs = subcommand ? [subcommand, ...commandArgs] : commandArgs
      await authCommand(authArgs, flags)
      break
    }
    case 'wizard': {
      // Lazy-load the wizard so the agent SDK is only imported when needed.
      const { run } = await import('../commands/wizard/run.js')
      await run({
        cwd: process.cwd(),
        debug: flags.debug,
        cliVersion: pkg.version,
      })
      break
    }
    case 'db':
      await runDbCommand(subcommand, flags, values)
      break
    case 'encrypt':
      await runEncryptCommand(subcommand, flags, values)
      break
    case 'schema':
      await runSchemaCommand(subcommand, flags)
      break
    case 'env':
      await envCommand({ write: flags.write })
      break
    default:
      console.error(`Unknown command: ${command}\n`)
      console.log(HELP)
      process.exit(1)
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err)
  p.log.error(`Fatal error: ${message}`)
  process.exit(1)
})
