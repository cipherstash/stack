import { config } from 'dotenv'

// Load env files in Next.js precedence order. dotenv's default behavior is to
// not overwrite vars that are already set, so loading .env.local first means
// its values win over .env for the same keys. Users can still set anything in
// the real environment to override both.
//
// `quiet: true` suppresses dotenv v17's `injected env (N) from …` banner,
// which it now prints to stdout on every `config()` call. Without it the CLI
// emits four noisy, non-deterministic banner lines (with rotating tips) ahead
// of its own output on every invocation — restoring the silent behaviour of
// dotenv v16.
config({ path: '.env.local', quiet: true })
config({ path: '.env.development.local', quiet: true })
config({ path: '.env.development', quiet: true })
config({ path: '.env', quiet: true })

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as p from '@clack/prompts'
import { renderCommandHelp } from '../cli/help.js'
// Commands that depend on @cipherstash/stack are lazy-loaded in the switch below.
import {
  authCommand,
  dbStatusCommand,
  envCommand,
  implCommand,
  initCommand,
  installCommand,
  manifestCommand,
  planCommand,
  statusCommand,
  telemetryCommand,
  testConnectionCommand,
  upgradeCommand,
  wizardCommand,
} from '../commands/index.js'
import { messages } from '../messages.js'
import {
  initTelemetry,
  maybeShowFirstRunNotice,
  shutdownTelemetry,
  trackCommand,
} from '../telemetry/index.js'

function isModuleNotFound(err: unknown): boolean {
  return (
    err instanceof Error &&
    'code' in err &&
    (err as { code: string }).code === 'ERR_MODULE_NOT_FOUND'
  )
}

import {
  detectPackageManager,
  prodInstallCommand,
  runnerCommand,
} from '../commands/init/utils.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf-8'),
)

// Detect once, share across help rendering and the requireStack hint.
// Detection reads `npm_config_user_agent` (when the user invoked via
// `bunx`/`pnpm dlx`/`yarn dlx`) and falls back to the lockfile in cwd.
const PM = detectPackageManager()
const STASH = runnerCommand(PM, 'stash')

async function requireStack<T>(importFn: () => Promise<T>): Promise<T> {
  try {
    return await importFn()
  } catch (err: unknown) {
    if (isModuleNotFound(err)) {
      p.log.error(
        `@cipherstash/stack is required for this command.
  Install it with: ${prodInstallCommand(PM, '@cipherstash/stack')}
  Or run: ${STASH} init`,
      )
      process.exit(1) as never
    }
    throw err
  }
}

const HELP = `
${messages.cli.versionBannerPrefix}${pkg.version}

${messages.cli.usagePrefix}${STASH} <command> [options]

Commands:
  init                 Initialize CipherStash for your project
  plan                 Draft a reviewable encryption plan at .cipherstash/plan.md
  impl                 Execute the plan with a local agent
  status               Displays implementation status
  auth <subcommand>    Authenticate with CipherStash
  wizard               AI-guided encryption setup (reads your codebase)
  doctor               Diagnose install problems (native binaries, runtime)
  manifest             Print the structured, versioned command surface (--json for docs/agents)
  telemetry <sub>      Manage anonymous usage analytics (status, enable, disable)

  eql install          Scaffold stash.config.ts (if missing) and install EQL extensions
  eql upgrade          Upgrade EQL extensions to the latest version
  eql status           Show EQL installation status

  db push              (EQL v2 + Proxy) Push encryption schema to eql_v2_configuration
  db activate          (EQL v2 + Proxy) Promote pending → active without renames
  db validate          Validate encryption schema
  db migrate           Run pending encrypt config migrations
  db test-connection   Test database connectivity

  schema build         Build an encryption schema from your database

  encrypt status       Show per-column migration status (phase, progress, drift)
  encrypt plan         Diff intent (.cipherstash/migrations.json) vs observed state
  encrypt backfill     Resumably encrypt plaintext into the encrypted column
  encrypt cutover      Rename swap encrypted → primary column
  encrypt drop         Generate a migration to drop the plaintext column

  env                  (experimental) Print production env vars for deployment

Options:
  --help, -h           Show help
  --version, -v        Show version

Run \`${STASH} <command> --help\` for a command's flags and examples
(e.g. \`${STASH} eql install --help\`, \`${STASH} auth login --help\`).

Examples:
  ${STASH} init                     # set up CipherStash in this project
  ${STASH} auth login               # authenticate
  ${STASH} eql install              # install EQL extensions
  ${STASH} manifest --json          # structured command surface for docs / agents
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
    } else if (arg === '-h') {
      // Short aliases for the two global boolean flags, normalized to their
      // long-form keys so downstream `flags.help` / `flags.version` checks catch
      // `stash <command> -h` too (not just a bare `stash -h`).
      flags.help = true
    } else if (arg === '-v') {
      flags.version = true
    } else {
      commandArgs.push(arg)
    }
  }

  return { command, subcommand, commandArgs, flags, values }
}

async function runInstall(
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
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
    eqlVersion: values['eql-version'],
    databaseUrl: values['database-url'],
    // An explicit `--database-url` is a one-shot install against that DB — leave
    // the project untouched. Otherwise offer to scaffold a config for later.
    scaffoldConfig: values['database-url'] !== undefined ? 'skip' : 'offer',
  })
}

async function runUpgrade(
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
  await upgradeCommand({
    dryRun: flags['dry-run'],
    supabase: flags.supabase,
    excludeOperatorFamily: flags['exclude-operator-family'],
    latest: flags.latest,
    eqlVersion: values['eql-version'],
    databaseUrl: values['database-url'],
  })
}

async function runEqlCommand(
  sub: string | undefined,
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
  switch (sub) {
    case 'install':
      await runInstall(flags, values)
      break
    case 'upgrade':
      await runUpgrade(flags, values)
      break
    case 'status':
      await dbStatusCommand({ databaseUrl: values['database-url'] })
      break
    default:
      p.log.error(`${messages.eql.unknownSubcommand}: ${sub ?? '(none)'}`)
      console.log()
      console.log(HELP)
      process.exit(1)
  }
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
    // Deprecated aliases — these commands moved to the `eql` group. Keep the
    // old spellings working so existing scripts and published docs don't
    // break.
    case 'install':
      p.log.warn(messages.db.aliasDeprecated(STASH, 'install'))
      await runInstall(flags, values)
      break
    case 'upgrade':
      p.log.warn(messages.db.aliasDeprecated(STASH, 'upgrade'))
      await runUpgrade(flags, values)
      break
    case 'push': {
      const { pushCommand } = await requireStack(
        () => import('../commands/db/push.js'),
      )
      await pushCommand({ dryRun: flags['dry-run'], databaseUrl })
      break
    }
    case 'activate': {
      const { activateCommand } = await requireStack(
        () => import('../commands/db/activate.js'),
      )
      await activateCommand({ databaseUrl })
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
      p.log.warn(messages.db.aliasDeprecated(STASH, 'status'))
      await dbStatusCommand({ databaseUrl })
      break
    case 'test-connection':
      await testConnectionCommand({ databaseUrl })
      break
    case 'migrate':
      p.log.warn(messages.db.migrateNotImplemented(STASH))
      break
    default:
      p.log.error(`${messages.db.unknownSubcommand}: ${sub ?? '(none)'}`)
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
        confirmDualWritesDeployed: flags['confirm-dual-writes-deployed'],
        force: flags.force,
      })
      break
    }
    case 'cutover': {
      const table = requireValue(values, 'table')
      const column = requireValue(values, 'column')
      const { cutoverCommand } = await requireStack(
        () => import('../commands/encrypt/cutover.js'),
      )
      await cutoverCommand({
        table,
        column,
        proxyUrl: values['proxy-url'],
        migrationsDir: values['migrations-dir'],
      })
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

// The CLI body. Loaded by the thin launcher in stash.ts via dynamic import so
// that a missing native binary (evaluated when this module's command graph
// loads) surfaces as friendly guidance rather than a raw stack trace.
export async function run() {
  const { command, subcommand, commandArgs, flags, values } = parseArgs(
    process.argv,
  )

  if (!command || command === '--help' || command === '-h') {
    console.log(HELP)
    return
  }

  if (command === '--version' || command === '-v' || flags.version) {
    console.log(pkg.version)
    return
  }

  // `stash <command> --help` / `-h`: render command-specific help from the
  // descriptor registry (e.g. `stash eql --help`, `stash eql install --help`).
  // Falls back to the global banner when the command path matches no descriptor.
  if (flags.help) {
    const path = subcommand ? `${command} ${subcommand}` : command
    console.log(renderCommandHelp(path, STASH) ?? HELP)
    return
  }

  // Anonymous, opt-out usage analytics. The notice shows once (to stderr) and
  // the run that shows it sends nothing; both are no-ops when telemetry is off.
  initTelemetry(pkg.version)
  maybeShowFirstRunNotice(STASH)

  const startedAt = Date.now()
  let succeeded = true
  let errorType: string | undefined

  try {
    await dispatch(command, subcommand, commandArgs, flags, values)
  } catch (err) {
    succeeded = false
    errorType = err instanceof Error ? err.constructor.name : 'Unknown'
    throw err
  } finally {
    trackCommand({
      command,
      subcommand,
      success: succeeded,
      durationMs: Date.now() - startedAt,
      errorType,
    })
    await shutdownTelemetry()
  }
}

async function dispatch(
  command: string,
  subcommand: string | undefined,
  commandArgs: string[],
  flags: Record<string, boolean>,
  values: Record<string, string>,
) {
  switch (command) {
    case 'init':
      await initCommand(flags, values)
      break
    case 'plan':
      await planCommand(flags, values)
      break
    case 'impl':
      await implCommand(flags, values)
      break
    case 'status':
      await statusCommand({
        quest: flags.quest,
        plain: flags.plain,
        json: flags.json,
      })
      break
    case 'auth': {
      const authArgs = subcommand ? [subcommand, ...commandArgs] : commandArgs
      await authCommand(authArgs, flags, values)
      break
    }
    case 'eql':
      await runEqlCommand(subcommand, flags, values)
      break
    case 'db':
      await runDbCommand(subcommand, flags, values)
      break
    case 'encrypt':
      await runEncryptCommand(subcommand, flags, values)
      break
    case 'schema':
      await runSchemaCommand(subcommand, flags, values)
      break
    case 'env':
      await envCommand({ write: flags.write })
      break
    case 'manifest':
      // Pure metadata (no native code) — safe to run anywhere, including when
      // the native binary is missing.
      manifestCommand({ json: flags.json, version: pkg.version })
      break
    case 'telemetry':
      await telemetryCommand(subcommand)
      break
    case 'wizard': {
      // Forward everything after `stash wizard` verbatim. The wizard package
      // owns its own flag parsing; we don't try to interpret its surface
      // here so it can evolve independently.
      const wizardArgs = process.argv.slice(3)
      await wizardCommand(wizardArgs)
      break
    }
    case 'doctor': {
      // Normally intercepted by the launcher before this module loads (so it
      // works even when the native binary is missing); handled here too so the
      // command still runs if run() is invoked directly.
      const { doctorCommand } = await import('../commands/doctor/index.js')
      await doctorCommand()
      break
    }
    default:
      console.error(`${messages.cli.unknownCommand}: ${command}\n`)
      console.log(HELP)
      process.exit(1)
  }
}
