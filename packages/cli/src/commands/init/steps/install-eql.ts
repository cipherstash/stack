import * as p from '@clack/prompts'
import { CliExit } from '../../../cli/exit.js'
import { isInteractive } from '../../../config/tty.js'
import { pinnedSpec } from '../../../runtime-versions.js'
import { ensureEncryptionClient } from '../../db/client-scaffold.js'
import { offerStashConfig } from '../../db/config-scaffold.js'
import { detectSupabaseProject } from '../../db/detect.js'
import { installCommand } from '../../db/install.js'
import {
  type EqlMigrationOptions,
  eqlMigrationCommand,
} from '../../eql/migration.js'
import { findExistingEqlMigration } from '../../eql/supabase-migration.js'
import type { InitProvider, InitState, InitStep } from '../types.js'
import { CancelledError } from '../types.js'
import { isPackageInstalled } from '../utils.js'

/**
 * Whether this project has a local `supabase/` directory to write a migration
 * into. `config.toml` is the stronger signal — `supabase init` writes it before
 * any migration exists — but an imported project may carry only the migrations
 * directory, so either counts.
 */
function hasLocalSupabaseScaffolding(): boolean {
  const project = detectSupabaseProject(process.cwd())
  return project.hasConfigToml || project.hasMigrationsDir
}

/**
 * Re-running `stash init --supabase` over a project that already has an install
 * migration is a no-op, not a failure.
 *
 * `eql migration --supabase` refuses to write a second one, so without this the
 * generate call throws, the catch below reports a write failure, and `initCommand`
 * sees no `eqlMigrationPending` — printing "✗ EQL extension NOT installed",
 * telling the user to run the direct `stash eql install` this route exists to
 * avoid, and exiting 1. Nothing is wrong: the migration is right there.
 *
 * Passing `force: true` from init would also unblock it, but that silently
 * rewrites a file some environment may already have applied.
 */
function existingSupabaseMigration(): string | null {
  const { migrationsDir } = detectSupabaseProject(process.cwd())
  return findExistingEqlMigration(migrationsDir)
}

/**
 * `eql migration` deliberately does no config/client scaffolding of its own
 * (unlike `eql install`), so init does it here — otherwise the migration-first
 * routes would silently skip half the init contract every other integration
 * gets (#581).
 *
 * Every migration-first exit runs this, including the one that finds the
 * migration already written: a project whose migration came from a standalone
 * `stash eql migration --supabase` has never had a `stash.config.ts` written,
 * and skipping it here would report "Setup complete" over a project that
 * cannot load one.
 */
async function scaffoldConfigAndClient(state: InitState): Promise<void> {
  const clientPath = await offerStashConfig({ ensure: true })
  if (clientPath) {
    ensureEncryptionClient(clientPath, process.cwd(), state.databaseUrl)
  }
}

/**
 * A migration-first route: one of the two branches that WRITE an EQL migration
 * file rather than touching the database.
 *
 * Resolved as a value before the confirm prompt so the prompt, the
 * non-interactive notice, and the decline hint can all name what will actually
 * happen. They used to be written for the direct-install route and reused
 * verbatim on every route — the prompt asked about installing into the
 * database and then wrote a file, and declining pointed a Drizzle or Supabase
 * user at `stash eql install`, the one command each route exists to avoid.
 */
interface MigrationRoute {
  /** Which branch this is. Only `supabase` can find a migration already on
   *  disk (`eql migration --drizzle` shells out to drizzle-kit, which owns
   *  duplicate detection itself). */
  kind: 'drizzle' | 'supabase'
  /** Confirm-prompt copy. Keeps the "(required for encryption)" force of the
   *  direct-install prompt — declining is not a neutral choice on any route. */
  prompt: string
  options: EqlMigrationOptions
  retryCommand: string
  failureHint: string
}

/**
 * Which migration-first route, if any, this project takes — EQL v3 either way.
 *
 * **Drizzle.** `eql install --drizzle` is v2-only: under the v3 default it
 * rejects the flag outright, so routing Drizzle through it would provision a
 * v2 database while every other integration (and a bare `stash eql install`)
 * gets v3. That also contradicts the stash-drizzle skill installed into the
 * very same project, which documents the v3 surface (`types.*` domains,
 * `Encryption`) and would have the user's agent author v3 code against a v2
 * database. `stash eql migration --drizzle` (added in #691) closes that gap:
 * v3 SQL, still migration-first, and it bundles the `cs_migrations` tracking
 * schema so one `drizzle-kit migrate` covers everything `stash encrypt` needs.
 *
 * **Supabase.** Same migration-first shape, different motivation. A direct
 * install works, and then `supabase db reset` — the ordinary local development
 * loop — drops the database and replays supabase/migrations/, taking EQL with
 * it. Writing the install into that directory is the only way it survives
 * (#613). It also means one `db reset` provisions everything `stash encrypt`
 * needs, since the emitted SQL carries `cs_migrations` too. Gated on local CLI
 * scaffolding: a project pointed at a hosted Supabase database with no
 * `supabase/` directory has nowhere to write and no `supabase` binary to apply
 * it with, so it must keep installing directly.
 *
 * Drizzle wins when both signals fire — it owns the migration history there,
 * and `--supabase` degrades to the grants modifier it has always been on that
 * path. `initCommand`'s apply-step routing makes the same call, for the same
 * reason. The `&&` short-circuit keeps the filesystem probe off every
 * non-Supabase project.
 */
function resolveMigrationRoute(
  supabase: boolean,
  drizzle: boolean,
): MigrationRoute | null {
  if (drizzle) {
    return {
      kind: 'drizzle',
      prompt:
        'Generate an EQL migration in your Drizzle migrations folder now? (required for encryption)',
      options: { drizzle: true, supabase: supabase || undefined },
      retryCommand: 'stash eql migration --drizzle',
      failureHint:
        'Could not generate the EQL migration — check that drizzle-kit is installed and configured.',
    }
  }
  if (supabase && hasLocalSupabaseScaffolding()) {
    return {
      kind: 'supabase',
      prompt:
        'Generate an EQL migration in supabase/migrations/ now? (required for encryption)',
      options: { supabase: true },
      retryCommand: 'stash eql migration --supabase',
      failureHint:
        'Could not write the EQL migration into supabase/migrations/.',
    }
  }
  return null
}

/**
 * Shared body of the two migration-first routes.
 *
 * The failure path never echoes the underlying error: `eqlMigrationCommand`
 * has already logged its own actionable diagnostics, and errors on this path
 * can carry a connection string.
 */
async function generateEqlMigration(
  state: InitState,
  route: MigrationRoute,
): Promise<InitState> {
  await scaffoldConfigAndClient(state)

  try {
    await eqlMigrationCommand({ ...route.options, embedded: true })
  } catch {
    p.log.error(route.failureHint)
    p.note(`Re-run with: ${route.retryCommand}`, 'You can retry manually')
    return { ...state, eqlInstalled: false }
  }

  // A migration file was WRITTEN, not applied — EQL lands in the database when
  // the user runs their migrate step.
  return { ...state, eqlInstalled: false, eqlMigrationPending: true }
}

/**
 * Install EQL programmatically after a y/N confirm.
 *
 * Two routes, both EQL v3. Migration-first wherever the project has a
 * migration history to land in — Drizzle projects (`stash eql migration
 * --drizzle`), and Supabase projects with local CLI scaffolding (`stash eql
 * migration --supabase`). Everything else runs `stash eql install` directly.
 *
 * EQL is the Postgres extension every CipherStash query relies on. Without
 * it, the encryption client can't read or write to encrypted columns.
 * Skipping isn't a dead end — the action prompt fed to the agent will note
 * it as the first thing to run before any migration.
 *
 * We pass the URL we already resolved at the start of init (state.databaseUrl)
 * through to `installCommand` so the user is never re-prompted.
 *
 * `installCommand` ends init on a hard failure (mutually-exclusive flag clash,
 * scaffold cancellation, an unsafe `--name`) — either by calling
 * `process.exit(1)` directly or by throwing `CliExit`, which the catch below
 * re-throws. That's fine — by that point the user has already authenticated
 * and written the encryption client, and a clean exit is preferable to a
 * half-installed setup.
 */
export const installEqlStep: InitStep = {
  id: 'install-eql',
  name: 'Install EQL extension',
  async run(state: InitState, provider: InitProvider): Promise<InitState> {
    const integration = state.integration ?? 'postgresql'

    // Prisma Next ships the EQL bundle as a baseline migration inside
    // `@cipherstash/stack-prisma`. `prisma-next migrate` runs
    // it in the same control-plane sweep as the user's application
    // migrations — running `stash eql install` here would be a
    // duplicate install and would race with the framework's
    // migration journal. Skip with guidance instead.
    if (integration === 'prisma-next' || provider.selected.includes('prisma')) {
      p.log.success(
        'Skipping `stash eql install` — Prisma Next installs the EQL bundle via `prisma-next migrate` (runs alongside your app migrations).',
      )
      return { ...state, eqlInstalled: false }
    }

    // Two signals per integration: what the project looks like, and what the
    // user asked for. The flag half reads `provider.selected` rather than
    // `provider.name` because the flags combine — `stash init --drizzle
    // --supabase` names itself 'drizzle-supabase', which equals neither, so
    // both went false, `resolveMigrationRoute` returned null, and a local
    // Supabase + Drizzle project (integration 'postgresql', because the host is
    // 127.0.0.1:54322) got a direct install with no migration file and no role
    // grants — the #613 failure, reached through a flag combination the CLI
    // accepts.
    const supabase =
      integration === 'supabase' || provider.selected.includes('supabase')
    const drizzle =
      integration === 'drizzle' || provider.selected.includes('drizzle')

    // Resolved BEFORE the prompt, not at the branch below, because everything
    // the user reads next has to describe the route they are actually on.
    // Both inputs are already available here: the two flags above, and a pair
    // of `existsSync` calls behind `hasLocalSupabaseScaffolding()`.
    const migrationRoute = resolveMigrationRoute(supabase, drizzle)

    // Non-interactive (CI, agents, pipes): there's no TTY to answer the prompt,
    // so take the default (proceed) and continue rather than hang or abort. This
    // is what makes `stash init` honour its documented non-interactive contract.
    if (!isInteractive()) {
      p.log.info(
        migrationRoute
          ? 'Generating the EQL migration (non-interactive).'
          : 'Installing the EQL extension (non-interactive).',
      )
    }
    const proceed = isInteractive()
      ? await p.confirm({
          message:
            migrationRoute?.prompt ??
            'Install the EQL extension into your database now? (required for encryption)',
          initialValue: true,
        })
      : true

    if (p.isCancel(proceed)) throw new CancelledError()

    if (!proceed) {
      p.log.info('Skipping EQL installation.')
      p.note(
        migrationRoute
          ? `Run \`${migrationRoute.retryCommand}\`, then apply it before any migration that references encrypted columns.`
          : 'Run `stash eql install` before applying any migration that references encrypted columns.',
        'EQL not installed',
      )
      return { ...state, eqlInstalled: false }
    }

    // installCommand scaffolds stash.config.ts (which `import`s from `stash`)
    // for the rest of the workflow. `stash` must be installed or the config the
    // user relies on next (db validate / encrypt) can't load. Detect
    // the precondition and bail with a clear message instead. install-deps is
    // what installs the package, so a "no" there leaves us here.
    if (!isPackageInstalled('stash')) {
      p.log.error(
        '`stash` is not installed in this project. The previous step (install-deps) was skipped or failed. Re-run `stash init` and accept the dependency install when prompted, or install it manually:',
      )
      // Pinned to this release's version (#661) — a bare `stash` here resolves
      // the `latest` dist-tag, which can lag during pre-release windows.
      const spec = pinnedSpec('stash')
      p.note(
        `  npm install --save-dev ${spec}\n  pnpm add -D ${spec}\n  yarn add -D ${spec}\n  bun add -D ${spec}`,
        'Then re-run init',
      )
      return { ...state, eqlInstalled: false }
    }

    // The migration-first routes (see `resolveMigrationRoute` for why each one
    // exists). `eql migration` does none of `eql install`'s config/client
    // scaffolding, so `generateEqlMigration` does it here to keep the rest of
    // the init contract identical.
    if (migrationRoute) {
      if (migrationRoute.kind === 'supabase') {
        const existing = existingSupabaseMigration()
        if (existing) {
          // Still scaffold: the migration may have come from a standalone `stash
          // eql migration --supabase`, which writes SQL and nothing else.
          await scaffoldConfigAndClient(state)
          p.log.success(`EQL install migration already present: ${existing}`)
          // `eqlMigrationAlreadyPresent` is what stops the summary claiming
          // this run "generated" a file it only found. The apply guidance is
          // unchanged — an unapplied migration is an unapplied migration — so
          // `eqlMigrationPending` still carries the completeness signal.
          return {
            ...state,
            eqlInstalled: false,
            eqlMigrationPending: true,
            eqlMigrationAlreadyPresent: true,
          }
        }
      }
      return await generateEqlMigration(state, migrationRoute)
    }

    try {
      await installCommand({
        supabase: supabase || undefined,
        databaseUrl: state.databaseUrl,
        // init passes a resolved URL to avoid re-prompting, but still wants a
        // config scaffolded — this is NOT a one-shot `--database-url` run.
        scaffoldConfig: 'ensure',
      })
    } catch (error) {
      // A cooperative exit is a hard stop the installer already reported on
      // (it printed its own actionable error and outro). Re-throw so it
      // unwinds to `run()` and exits, rather than being reframed below as a
      // database-connection problem and letting init continue.
      if (error instanceof CliExit) throw error
      // Don't echo the underlying error — Postgres client errors routinely
      // include the connection string (with credentials) in the message,
      // and `state.databaseUrl` flows into this code path.
      p.log.error(
        'EQL install failed — check your database connection and try again.',
      )
      p.note('Re-run with: stash eql install', 'You can retry manually')
      return { ...state, eqlInstalled: false }
    }

    // 'installed' | 'already-installed' — the extension is present in the DB.
    // ('dry-run' never happens from init; it doesn't pass dryRun.)
    return { ...state, eqlInstalled: true }
  },
}
