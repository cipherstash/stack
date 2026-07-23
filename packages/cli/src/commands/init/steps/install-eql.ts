import * as p from '@clack/prompts'
import { CliExit } from '../../../cli/exit.js'
import { isInteractive } from '../../../config/tty.js'
import { pinnedSpec } from '../../../runtime-versions.js'
import { ensureEncryptionClient } from '../../db/client-scaffold.js'
import { offerStashConfig } from '../../db/config-scaffold.js'
import { installCommand } from '../../db/install.js'
import { eqlMigrationCommand } from '../../eql/migration.js'
import type { InitProvider, InitState, InitStep } from '../types.js'
import { CancelledError } from '../types.js'
import { isPackageInstalled } from '../utils.js'

/**
 * Install EQL programmatically after a y/N confirm.
 *
 * Two routes, both EQL v3: Drizzle projects generate a v3 install migration
 * (`stash eql migration --drizzle`) so the install lands in the project's
 * migration history; everything else runs `stash eql install` directly.
 *
 * EQL is the Postgres extension every CipherStash query relies on. Without
 * it, the encryption client can't read or write to encrypted columns.
 * Skipping isn't a dead end — the action prompt fed to the agent will note
 * it as the first thing to run before any migration.
 *
 * We pass the URL we already resolved at the start of init (state.databaseUrl)
 * through to `installCommand` so the user is never re-prompted. The installer
 * picks the Supabase migration / direct mode itself based on `--supabase` and
 * project layout — we don't pre-decide it here.
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
    // `@cipherstash/prisma-next`. `prisma-next migrate` runs
    // it in the same control-plane sweep as the user's application
    // migrations — running `stash eql install` here would be a
    // duplicate install and would race with the framework's
    // migration journal. Skip with guidance instead.
    if (integration === 'prisma-next' || provider.name === 'prisma-next') {
      p.log.success(
        'Skipping `stash eql install` — Prisma Next installs the EQL bundle via `prisma-next migrate` (runs alongside your app migrations).',
      )
      return { ...state, eqlInstalled: false }
    }

    const supabase = integration === 'supabase' || provider.name === 'supabase'
    const drizzle = integration === 'drizzle' || provider.name === 'drizzle'

    // Non-interactive (CI, agents, pipes): there's no TTY to answer the prompt,
    // so take the default (install) and continue rather than hang or abort. This
    // is what makes `stash init` honour its documented non-interactive contract.
    if (!isInteractive()) {
      p.log.info('Installing the EQL extension (non-interactive).')
    }
    const proceed = isInteractive()
      ? await p.confirm({
          message:
            'Install the EQL extension into your database now? (required for encryption)',
          initialValue: true,
        })
      : true

    if (p.isCancel(proceed)) throw new CancelledError()

    if (!proceed) {
      p.log.info('Skipping EQL installation.')
      p.note(
        'Run `stash eql install` before applying any migration that references encrypted columns.',
        'EQL not installed',
      )
      return { ...state, eqlInstalled: false }
    }

    // installCommand scaffolds stash.config.ts (which `import`s from `stash`)
    // for the rest of the workflow. `stash` must be installed or the config the
    // user relies on next (db push / schema build / encrypt) can't load. Detect
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

    // Drizzle: generate an EQL **v3** migration (`stash eql migration
    // --drizzle`) rather than routing through `eql install`.
    //
    // `eql install --drizzle` is v2-only — under the v3 default it rejects the
    // flag outright, so init used to pin `eqlVersion: '2'` to get a migration
    // at all. That pin made `stash init --drizzle` the one flow that provisions
    // a v2 database while every other integration (and a bare `stash eql
    // install`) gets v3, and it contradicted the stash-drizzle skill we install
    // into the very same project — that skill documents the `/v3` surface
    // (`types.*` domains, `EncryptionV3`) and would have the user's agent
    // author v3 code against a v2 database.
    //
    // `stash eql migration --drizzle` (added in #691) closes that gap: v3 SQL,
    // still migration-first, and it bundles the `cs_migrations` tracking schema
    // so one `drizzle-kit migrate` covers everything `stash encrypt` needs.
    // `eql install`'s config/client scaffolding isn't part of that command, so
    // we do it here to keep the rest of the init contract identical.
    if (drizzle) {
      const clientPath = await offerStashConfig({ ensure: true })
      if (clientPath) {
        ensureEncryptionClient(clientPath, process.cwd(), state.databaseUrl)
      }

      try {
        await eqlMigrationCommand({
          drizzle: true,
          supabase: supabase || undefined,
          embedded: true,
        })
      } catch {
        // Most likely drizzle-kit missing or misconfigured. Don't echo the
        // error (same reasoning as below re: connection strings) — the command
        // has already logged its own actionable diagnostics.
        p.log.error(
          'Could not generate the EQL migration — check that drizzle-kit is installed and configured.',
        )
        p.note(
          'Re-run with: stash eql migration --drizzle',
          'You can retry manually',
        )
        return { ...state, eqlInstalled: false }
      }

      // A migration file was WRITTEN, not applied — EQL lands in the database
      // when the user runs `drizzle-kit migrate`.
      return { ...state, eqlInstalled: false, eqlMigrationPending: true }
    }

    let outcome: Awaited<ReturnType<typeof installCommand>>
    try {
      outcome = await installCommand({
        supabase: supabase || undefined,
        databaseUrl: state.databaseUrl,
        // No `eqlVersion` — take the v3 default. (The Drizzle branch above
        // returns before this point.)
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

    // Supabase `--migration` mode only WRITES a migration file — EQL isn't in
    // the database until the user applies it. (Drizzle is handled above.)
    // Report that honestly rather than claiming the extension is installed;
    // the init summary turns this into "migration generated, apply it".
    if (outcome === 'migration-generated') {
      return { ...state, eqlInstalled: false, eqlMigrationPending: true }
    }

    // 'installed' | 'already-installed' — the extension is present in the DB.
    // ('dry-run' never happens from init; it doesn't pass dryRun.)
    return { ...state, eqlInstalled: true }
  },
}
