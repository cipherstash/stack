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
import { messages } from '../messages.js'

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
${messages.cli.versionBannerPrefix}${pkg.version}

${messages.cli.usagePrefix} <command> [options]

Commands:
  init                 Initialize CipherStash for your project
  auth <subcommand>    Authenticate with CipherStash

  db install           Scaffold stash.config.ts (if missing) and install EQL extensions
  db upgrade           Upgrade EQL extensions to the latest version
  db push              Push encryption schema to database (CipherStash Proxy only)
  db validate          Validate encryption schema
  db migrate           Run pending encrypt config migrations
  db status            Show EQL installation status
  db test-connection   Test database connectivity

  schema build         Build an encryption schema from your database

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
  --database-url <url>       (all db / schema commands) Override DATABASE_URL for this run only — never written to disk

Examples:
  npx @cipherstash/cli init
  npx @cipherstash/cli init --supabase
  npx @cipherstash/cli auth login
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
  // Plumbed through every db subcommand so the URL resolver can use it as
  // an explicit override. See packages/cli/src/config/database-url.ts.
  const databaseUrl = values['database-url']

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
        databaseUrl,
      })
      break
    case 'upgrade':
      await upgradeCommand({
        dryRun: flags['dry-run'],
        supabase: flags.supabase,
        excludeOperatorFamily: flags['exclude-operator-family'],
        latest: flags.latest,
        databaseUrl,
      })
      break
    case 'push': {
      const { pushCommand } = await requireStack(
        () => import('../commands/db/push.js'),
      )
      await pushCommand({ dryRun: flags['dry-run'], databaseUrl })
      break
    }
    case 'validate': {
      const { validateCommand } = await requireStack(
        () => import('../commands/db/validate.js'),
      )
      await validateCommand({
        supabase: flags.supabase,
        excludeOperatorFamily: flags['exclude-operator-family'],
        databaseUrl,
      })
      break
    }
    case 'status':
      await statusCommand({ databaseUrl })
      break
    case 'test-connection':
      await testConnectionCommand({ databaseUrl })
      break
    case 'migrate':
      p.log.warn(messages.db.migrateNotImplemented)
      break
    default:
      p.log.error(`${messages.db.unknownSubcommand}: ${sub ?? '(none)'}`)
      console.log()
      console.log(HELP)
      process.exit(1)
  }
}

async function runSchemaCommand(
  sub: string | undefined,
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
  switch (sub) {
    case 'build': {
      const { builderCommand } = await requireStack(
        () => import('../commands/schema/build.js'),
      )
      await builderCommand({
        supabase: flags.supabase,
        databaseUrl: values['database-url'],
      })
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
    case 'db':
      await runDbCommand(subcommand, flags, values)
      break
    case 'schema':
      await runSchemaCommand(subcommand, flags, values)
      break
    case 'env':
      await envCommand({ write: flags.write })
      break
    default:
      console.error(`${messages.cli.unknownCommand}: ${command}\n`)
      console.log(HELP)
      process.exit(1)
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err)
  p.log.error(`Fatal error: ${message}`)
  process.exit(1)
})
