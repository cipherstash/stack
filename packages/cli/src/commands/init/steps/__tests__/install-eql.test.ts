import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

// installCommand is the unit under test's collaborator — mock it so we assert
// what init asks for without touching a database.
vi.mock('../../../db/install.js', () => ({ installCommand: vi.fn() }))
// The Drizzle and Supabase branches generate a v3 migration instead of calling
// installCommand.
vi.mock('../../../eql/migration.js', () => ({
  eqlMigrationCommand: vi.fn(async () => undefined),
}))
// Whether a Supabase project has local `supabase/` scaffolding decides between
// the migration and direct-install routes. Real detection walks the cwd (this
// package), which has neither — so toggle it per test.
vi.mock('../../../db/detect.js', async (importOriginal) => ({
  // Spread the original: replacing the whole module would leave
  // detectSupabase / detectDrizzle / detectPrismaNext undefined for anything
  // else that imports it. Nothing needs them today; this keeps it that way.
  ...(await importOriginal<typeof import('../../../db/detect.js')>()),
  detectSupabaseProject: vi.fn(() => ({
    hasConfigToml: false,
    hasMigrationsDir: false,
    migrationsDir: '/project/supabase/migrations',
  })),
}))
// Whether an install migration is already on disk decides between generating
// one and reporting the existing one as pending.
vi.mock('../../../eql/supabase-migration.js', () => ({
  findExistingEqlMigration: vi.fn(() => null),
}))
// `eql install` normally scaffolds these; the Drizzle branch does it itself.
vi.mock('../../../db/config-scaffold.js', () => ({
  offerStashConfig: vi.fn(async () => 'src/encryption/index.ts'),
}))
vi.mock('../../../db/client-scaffold.js', () => ({
  ensureEncryptionClient: vi.fn(),
}))
// `stash` must appear installed so the precondition guard doesn't short-circuit.
vi.mock('../../utils.js', () => ({ isPackageInstalled: vi.fn(() => true) }))
// Toggle interactivity per test (defaults to interactive in beforeEach).
vi.mock('../../../../config/tty.js', () => ({
  isInteractive: vi.fn(() => true),
}))
// Auto-approve the "install EQL now?" prompt; no-op the rest of clack.
vi.mock('@clack/prompts', () => ({
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: { info: vi.fn(), error: vi.fn(), success: vi.fn(), warn: vi.fn() },
  note: vi.fn(),
}))

import * as p from '@clack/prompts'
import { CliExit } from '../../../../cli/exit.js'
import { isInteractive } from '../../../../config/tty.js'
import { ensureEncryptionClient } from '../../../db/client-scaffold.js'
import { offerStashConfig } from '../../../db/config-scaffold.js'
import { detectSupabaseProject } from '../../../db/detect.js'
import { installCommand } from '../../../db/install.js'
import { eqlMigrationCommand } from '../../../eql/migration.js'
import { findExistingEqlMigration } from '../../../eql/supabase-migration.js'
import { installEqlStep } from '../install-eql.js'

/** Pretend the cwd has (or lacks) `supabase init` scaffolding. */
function withSupabaseScaffolding(present: boolean): void {
  vi.mocked(detectSupabaseProject).mockReturnValue({
    hasConfigToml: present,
    hasMigrationsDir: present,
    migrationsDir: '/project/supabase/migrations',
  })
}

/** The message the step put in front of the user before acting. */
function confirmMessage(): string {
  return vi.mocked(p.confirm).mock.calls[0][0].message
}

/** Every `p.note` body, joined — the step emits at most one per run. */
function noteBody(): string {
  return vi
    .mocked(p.note)
    .mock.calls.map(([body]) => body)
    .join('\n')
}

const supabaseState = {
  integration: 'supabase',
  databaseUrl: 'postgresql://localhost:54322/postgres',
} as unknown as InitState
const supabaseProvider = { name: 'supabase' } as unknown as InitProvider

const drizzleState = {
  integration: 'drizzle',
  databaseUrl: 'postgresql://localhost:5432/app',
} as unknown as InitState
const drizzleProvider = { name: 'drizzle' } as unknown as InitProvider

const baseState = {
  integration: 'postgresql',
  databaseUrl: 'postgresql://localhost:5432/app',
} as unknown as InitState
const provider = { name: 'postgresql' } as unknown as InitProvider

describe('installEqlStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(isInteractive).mockReturnValue(true)
    // clearAllMocks clears calls but keeps implementations, so a
    // mockReturnValue set in one test would leak into every later one.
    vi.mocked(findExistingEqlMigration).mockReturnValue(null)
  })

  it("requests scaffoldConfig: 'ensure' so init still creates a stash.config.ts (#581 regression)", async () => {
    // Regression guard: init passes a resolved databaseUrl only to avoid
    // re-prompting. If installCommand treated a present databaseUrl as a
    // one-shot `--database-url` run, init would finish with no config and every
    // downstream command would dead-end on 'Could not find stash.config.ts'.
    await installEqlStep.run(baseState, provider)

    expect(installCommand).toHaveBeenCalledTimes(1)
    const opts = vi.mocked(installCommand).mock.calls[0][0]
    expect(opts.scaffoldConfig).toBe('ensure')
    expect(opts.databaseUrl).toBe('postgresql://localhost:5432/app')
  })

  it('prompts before installing when interactive', async () => {
    await installEqlStep.run(baseState, provider)

    expect(p.confirm).toHaveBeenCalledTimes(1)
    expect(installCommand).toHaveBeenCalledTimes(1)
  })

  it('installs without prompting when non-interactive, and still scaffolds config (#600)', async () => {
    // In a non-TTY context (CI, agents, pipes) there is no way to answer the
    // prompt. init must proceed with the default (install) rather than abort,
    // and still scaffold stash.config.ts via the EQL install.
    vi.mocked(isInteractive).mockReturnValue(false)
    vi.mocked(installCommand).mockResolvedValueOnce('installed')

    const result = await installEqlStep.run(baseState, provider)

    expect(p.confirm).not.toHaveBeenCalled()
    expect(installCommand).toHaveBeenCalledTimes(1)
    expect(vi.mocked(installCommand).mock.calls[0][0].scaffoldConfig).toBe(
      'ensure',
    )
    expect(result.eqlInstalled).toBe(true)
    expect(result.eqlMigrationPending).toBeFalsy()
  })

  it('treats an already-installed database as EQL installed', async () => {
    vi.mocked(installCommand).mockResolvedValueOnce('already-installed')

    const result = await installEqlStep.run(baseState, provider)

    expect(result.eqlInstalled).toBe(true)
    expect(result.eqlMigrationPending).toBeFalsy()
  })

  it('never pins EQL v2 for the non-Drizzle paths', async () => {
    await installEqlStep.run(baseState, provider)

    expect(vi.mocked(installCommand).mock.calls[0][0]).not.toHaveProperty(
      'eqlVersion',
    )
  })

  describe('Prisma Next (`--prisma`)', () => {
    it('skips `stash eql install` when the provider is `prisma` (framework installs the bundle)', async () => {
      // `--prisma` sets provider.name === 'prisma'. Prisma Next installs the EQL
      // bundle via `prisma-next migrate`, so init must NOT run its own install —
      // that would duplicate the install and race the framework's journal.
      const prismaProvider = { name: 'prisma' } as unknown as InitProvider

      const result = await installEqlStep.run(
        { integration: 'prisma-next' } as unknown as InitState,
        prismaProvider,
      )

      expect(p.confirm).not.toHaveBeenCalled()
      expect(installCommand).not.toHaveBeenCalled()
      expect(eqlMigrationCommand).not.toHaveBeenCalled()
      expect(result.eqlInstalled).toBe(false)
    })
  })

  describe('Drizzle', () => {
    it('generates an EQL v3 migration instead of running `eql install` (the v2 pin is gone)', async () => {
      // Regression guard for the defect: init used to pass `eqlVersion: '2'` to
      // installCommand, making `stash init --drizzle` the ONLY flow that
      // provisioned a v2 database — while the stash-drizzle skill installed
      // into the same project documents the v3 surface. The Drizzle flow must
      // now go through `stash eql migration --drizzle`, which is v3.
      await installEqlStep.run(drizzleState, drizzleProvider)

      expect(installCommand).not.toHaveBeenCalled()
      expect(eqlMigrationCommand).toHaveBeenCalledTimes(1)
      expect(vi.mocked(eqlMigrationCommand).mock.calls[0][0]).toMatchObject({
        drizzle: true,
        embedded: true,
      })
    })

    it('maps a generated migration to eqlMigrationPending, NOT eqlInstalled', async () => {
      // The migration is only WRITTEN — EQL isn't in the DB until the user runs
      // `drizzle-kit migrate`. `installEqlStep` must carry that distinction
      // through so `initCommand` doesn't claim "EQL installed" (PR #687).
      const result = await installEqlStep.run(drizzleState, drizzleProvider)

      expect(result.eqlInstalled).toBe(false)
      expect(result.eqlMigrationPending).toBe(true)
      // This run really did generate it, so the summary's verb must stay
      // "generated" — only the already-on-disk branch sets this flag.
      expect(result.eqlMigrationAlreadyPresent).toBeFalsy()
    })

    it('scaffolds stash.config.ts + the client, which `eql install` would have done (#581)', async () => {
      // The Drizzle branch bypasses installCommand, so it owns the scaffolding
      // that `scaffoldConfig: 'ensure'` used to provide. Without this, init
      // would finish with no config and every downstream command would
      // dead-end on 'Could not find stash.config.ts'.
      await installEqlStep.run(drizzleState, drizzleProvider)

      expect(offerStashConfig).toHaveBeenCalledWith({ ensure: true })
      expect(ensureEncryptionClient).toHaveBeenCalledTimes(1)
    })

    it('forwards --supabase so a Drizzle-on-Supabase project gets the role grants', async () => {
      await installEqlStep.run(
        { ...drizzleState, integration: 'drizzle' } as InitState,
        { name: 'supabase' } as unknown as InitProvider,
      )

      expect(vi.mocked(eqlMigrationCommand).mock.calls[0][0].supabase).toBe(
        true,
      )
    })

    it('passes supabase: undefined for a plain (non-Supabase) Drizzle project', async () => {
      // Symmetric negative to the --supabase forward: a plain Drizzle project
      // must NOT leak supabase: true, or the migration would append role grants
      // no one asked for. `toMatchObject` above ignores the key, so it can't
      // catch a leak — this asserts it explicitly.
      await installEqlStep.run(drizzleState, drizzleProvider)

      expect(
        vi.mocked(eqlMigrationCommand).mock.calls[0][0].supabase,
      ).toBeUndefined()
    })

    it('still generates the migration when stash.config.ts already exists', async () => {
      // offerStashConfig returns null when the config is already on disk — the
      // re-run case (config-scaffold.ts: `if (existsSync(configPath)) return
      // null`), i.e. every re-run of `stash init` on a Drizzle project. Nothing
      // to scaffold, but the migration must still be written and the state must
      // still say "pending". If the `if (clientPath)` guard were dropped,
      // ensureEncryptionClient(null, …) would throw outside the try/catch and
      // abort init after the user has already authenticated.
      vi.mocked(offerStashConfig).mockResolvedValueOnce(null)

      const result = await installEqlStep.run(drizzleState, drizzleProvider)

      expect(ensureEncryptionClient).not.toHaveBeenCalled()
      expect(eqlMigrationCommand).toHaveBeenCalledTimes(1)
      expect(result.eqlMigrationPending).toBe(true)
      expect(result.eqlInstalled).toBe(false)
    })

    it('degrades to "not installed" (never crashes init) when drizzle-kit is missing', async () => {
      // eqlMigrationCommand throws CliExit when drizzle-kit isn't installed or
      // configured. init must absorb that and report honestly — a thrown
      // CliExit here would abort the whole run after the user has already
      // authenticated and had their client scaffolded.
      vi.mocked(eqlMigrationCommand).mockRejectedValueOnce(new Error('boom'))

      const result = await installEqlStep.run(drizzleState, drizzleProvider)

      expect(result.eqlInstalled).toBe(false)
      expect(result.eqlMigrationPending).toBeFalsy()
    })

    it('does not leak the database URL when the migration fails', async () => {
      // Same reasoning as the `eql install` catch: errors on this path can
      // carry a connection string with credentials.
      vi.mocked(eqlMigrationCommand).mockRejectedValueOnce(
        new Error('connect postgresql://user:hunter2@localhost:5432/app'),
      )

      await installEqlStep.run(drizzleState, drizzleProvider)

      const logged = [
        ...vi.mocked(p.log.error).mock.calls,
        ...vi.mocked(p.note).mock.calls,
      ]
        .flat()
        .join('\n')
      expect(logged).not.toContain('hunter2')
    })
  })

  describe('Supabase', () => {
    it('writes the install into supabase/migrations/ so it survives `db reset` (#613)', async () => {
      // The defect: init ran a direct `eql install`, and `supabase db reset` —
      // the ordinary local development loop — drops the database and replays
      // supabase/migrations/, taking EQL with it. The install has to be IN that
      // directory to come back.
      withSupabaseScaffolding(true)

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(installCommand).not.toHaveBeenCalled()
      expect(eqlMigrationCommand).toHaveBeenCalledTimes(1)
      expect(vi.mocked(eqlMigrationCommand).mock.calls[0][0]).toMatchObject({
        supabase: true,
        embedded: true,
      })
      // Not a Drizzle run — `--drizzle` would shell out to drizzle-kit, which
      // a plain Supabase project does not have.
      expect(
        vi.mocked(eqlMigrationCommand).mock.calls[0][0].drizzle,
      ).toBeFalsy()
    })

    it('maps the generated migration to eqlMigrationPending, NOT eqlInstalled', async () => {
      withSupabaseScaffolding(true)

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(result.eqlInstalled).toBe(false)
      expect(result.eqlMigrationPending).toBe(true)
    })

    it('scaffolds stash.config.ts + the client, which `eql install` would have done', async () => {
      withSupabaseScaffolding(true)

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(offerStashConfig).toHaveBeenCalledWith({ ensure: true })
      expect(ensureEncryptionClient).toHaveBeenCalledTimes(1)
    })

    it('installs directly when the project has no local supabase/ scaffolding', async () => {
      // A project pointed at a hosted Supabase database with no `supabase init`
      // has nowhere to write a migration and no `supabase` binary to apply one.
      // Routing it to the migration path would leave EQL uninstalled.
      withSupabaseScaffolding(false)

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(eqlMigrationCommand).not.toHaveBeenCalled()
      expect(installCommand).toHaveBeenCalledTimes(1)
      expect(vi.mocked(installCommand).mock.calls[0][0].supabase).toBe(true)
      expect(result.eqlInstalled).toBe(true)
    })

    it('degrades to "not installed" (never crashes init) when the write fails', async () => {
      withSupabaseScaffolding(true)
      vi.mocked(eqlMigrationCommand).mockRejectedValueOnce(new Error('boom'))

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(result.eqlInstalled).toBe(false)
      expect(result.eqlMigrationPending).toBeFalsy()
    })

    it('does not leak the database URL when the write fails', async () => {
      withSupabaseScaffolding(true)
      vi.mocked(eqlMigrationCommand).mockRejectedValueOnce(
        new Error('connect postgresql://user:hunter2@localhost:54322/postgres'),
      )

      await installEqlStep.run(supabaseState, supabaseProvider)

      const logged = [
        ...vi.mocked(p.log.error).mock.calls,
        ...vi.mocked(p.note).mock.calls,
      ]
        .flat()
        .join('\n')
      expect(logged).not.toContain('hunter2')
    })

    it('re-running init over an existing install migration is a no-op, not a failure', async () => {
      // Regression: `eql migration --supabase` refuses to write a second
      // install migration, so a second `stash init --supabase` used to take the
      // catch branch, return no `eqlMigrationPending`, and make initCommand
      // report "✗ EQL extension NOT installed" and exit 1 — pointing the user
      // at the direct `stash eql install` this route exists to avoid. Nothing
      // is wrong with the project: the migration is right there.
      withSupabaseScaffolding(true)
      vi.mocked(findExistingEqlMigration).mockReturnValue(
        '/project/supabase/migrations/20260804021925_cipherstash_eql.sql',
      )

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(eqlMigrationCommand).not.toHaveBeenCalled()
      expect(installCommand).not.toHaveBeenCalled()
      expect(result.eqlMigrationPending).toBe(true)
      expect(result.eqlInstalled).toBe(false)
    })

    it('marks the pending migration as already present, not freshly generated', async () => {
      // `eqlMigrationPending` alone cannot tell "written this run" from "found
      // on disk": both routes set it, and both want the same apply guidance.
      // Without a second signal `initCommand` prints "EQL migration generated"
      // over a run that generated nothing — a claim the user can disprove from
      // their own diff.
      withSupabaseScaffolding(true)
      vi.mocked(findExistingEqlMigration).mockReturnValue(
        '/project/supabase/migrations/20260804021925_cipherstash_eql.sql',
      )

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(result.eqlMigrationAlreadyPresent).toBe(true)
    })

    it('does not mark a migration it wrote this run as already present', async () => {
      // The symmetric negative: `findExistingEqlMigration` returns null, the
      // step writes the file, and the summary must still say "generated".
      withSupabaseScaffolding(true)

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(result.eqlMigrationPending).toBe(true)
      expect(result.eqlMigrationAlreadyPresent).toBeFalsy()
    })

    it('names the existing migration so the user knows what to apply', async () => {
      withSupabaseScaffolding(true)
      vi.mocked(findExistingEqlMigration).mockReturnValue(
        '/project/supabase/migrations/20260804021925_cipherstash_eql.sql',
      )

      await installEqlStep.run(supabaseState, supabaseProvider)

      const logged = vi
        .mocked(p.log.info)
        .mock.calls.flat()
        .concat(vi.mocked(p.log.success).mock.calls.flat())
        .join('\n')
      expect(logged).toContain('20260804021925_cipherstash_eql.sql')
    })

    it('still scaffolds stash.config.ts when the migration is already there', async () => {
      // The scaffolding is not the migration's job — `eql migration` writes SQL
      // and nothing else, so init supplies the config and client every other
      // route gets (the #581 contract). Skipping the generate call must not
      // skip that too: a project whose migration came from a standalone `stash
      // eql migration --supabase` has never had a stash.config.ts written, and
      // init would report "Setup complete" over a project that cannot load one.
      withSupabaseScaffolding(true)
      vi.mocked(findExistingEqlMigration).mockReturnValue(
        '/project/supabase/migrations/20260804021925_cipherstash_eql.sql',
      )

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(offerStashConfig).toHaveBeenCalledWith({ ensure: true })
      expect(ensureEncryptionClient).toHaveBeenCalledTimes(1)
    })

    it('keeps a Supabase-hosted Drizzle project on the Drizzle route', async () => {
      // Both signals are true here. Drizzle owns the migration history, so it
      // must win — `--supabase` degrades to the grants modifier it has always
      // been on that path.
      withSupabaseScaffolding(true)

      await installEqlStep.run(
        { ...drizzleState, integration: 'drizzle' } as InitState,
        supabaseProvider,
      )

      expect(vi.mocked(eqlMigrationCommand).mock.calls[0][0]).toMatchObject({
        drizzle: true,
        supabase: true,
      })
    })
  })

  describe('the confirm prompt names the action the route will take', () => {
    // The prompt is the user's only description of what pressing `y` does, and
    // two of the three routes never touch the database — they write a file.
    // "Install the EQL extension into your database now?" followed by a
    // generated migration described the wrong action on both of them.

    it('offers a database install on the direct route', async () => {
      await installEqlStep.run(baseState, provider)

      expect(confirmMessage()).toContain(
        'Install the EQL extension into your database',
      )
      expect(confirmMessage()).toContain('(required for encryption)')
    })

    it('offers a generated migration on the Drizzle route', async () => {
      await installEqlStep.run(drizzleState, drizzleProvider)

      expect(confirmMessage()).toMatch(/migration/i)
      expect(confirmMessage()).not.toContain(
        'Install the EQL extension into your database',
      )
      expect(confirmMessage()).toContain('(required for encryption)')
    })

    it('names supabase/migrations/ on the Supabase migration route', async () => {
      withSupabaseScaffolding(true)

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(confirmMessage()).toContain('supabase/migrations/')
      expect(confirmMessage()).not.toContain(
        'Install the EQL extension into your database',
      )
      expect(confirmMessage()).toContain('(required for encryption)')
    })

    it('keeps the database-install wording for a hosted Supabase project', async () => {
      // No local scaffolding means the direct route, so the prompt must follow
      // the ROUTING, not the `--supabase` flag.
      withSupabaseScaffolding(false)

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(confirmMessage()).toContain(
        'Install the EQL extension into your database',
      )
    })

    it('still defaults to yes on a migration-first route', async () => {
      withSupabaseScaffolding(true)

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(vi.mocked(p.confirm).mock.calls[0][0].initialValue).toBe(true)
    })
  })

  describe('declining the prompt', () => {
    // The retry hint has to name the command for the route the step WOULD have
    // taken. `stash eql install` is right for exactly one of the three.

    it('points the direct route at `stash eql install`', async () => {
      vi.mocked(p.confirm).mockResolvedValueOnce(false)

      const result = await installEqlStep.run(baseState, provider)

      expect(result.eqlInstalled).toBe(false)
      expect(installCommand).not.toHaveBeenCalled()
      expect(noteBody()).toContain('stash eql install')
    })

    it('points the Drizzle route at `stash eql migration --drizzle`', async () => {
      // `stash eql install --drizzle` is v2-only — under the v3 default it
      // rejects the flag outright — and a bare direct install never lands in
      // the migration history the project ships from. Sending a declining
      // Drizzle user there is sending them at the one command this route
      // exists to avoid.
      vi.mocked(p.confirm).mockResolvedValueOnce(false)

      const result = await installEqlStep.run(drizzleState, drizzleProvider)

      expect(result.eqlInstalled).toBe(false)
      expect(eqlMigrationCommand).not.toHaveBeenCalled()
      expect(noteBody()).toContain('stash eql migration --drizzle')
    })

    it('points the Supabase migration route at `stash eql migration --supabase`', async () => {
      // Retrying with `stash eql install --supabase` here reinstates the #613
      // defect outright: the install is wiped by the next `supabase db reset`.
      withSupabaseScaffolding(true)
      vi.mocked(p.confirm).mockResolvedValueOnce(false)

      const result = await installEqlStep.run(supabaseState, supabaseProvider)

      expect(result.eqlInstalled).toBe(false)
      expect(eqlMigrationCommand).not.toHaveBeenCalled()
      expect(noteBody()).toContain('stash eql migration --supabase')
    })

    it('points a hosted Supabase project at `stash eql install`', async () => {
      // Same flag, other side of the routing fork: with no `supabase/`
      // directory there is nowhere to write a migration, so the direct install
      // really is the retry command.
      withSupabaseScaffolding(false)
      vi.mocked(p.confirm).mockResolvedValueOnce(false)

      await installEqlStep.run(supabaseState, supabaseProvider)

      expect(noteBody()).toContain('stash eql install')
      expect(noteBody()).not.toContain('stash eql migration')
    })
  })

  it('re-throws CliExit instead of reframing it as a connection failure', async () => {
    // `installCommand` throws CliExit for hard stops it has ALREADY reported on
    // with its own actionable error (e.g. an unsafe `--name`). The broad catch
    // below it must not swallow that: doing so prints "check your database
    // connection" for a problem that has nothing to do with the database, and
    // lets init continue past a hard stop. Re-throwing unwinds to `run()`,
    // which records the outcome and exits with the carried code.
    vi.mocked(installCommand).mockRejectedValueOnce(new CliExit(1))

    await expect(
      installEqlStep.run(baseState, provider),
    ).rejects.toBeInstanceOf(CliExit)
    expect(p.log.error).not.toHaveBeenCalled()
  })

  it('still swallows a non-CliExit failure and lets init continue', async () => {
    // The contrast that gives the test above its meaning: an ordinary throw is
    // reported generically and init carries on. The message is deliberately
    // generic — Postgres client errors routinely carry the connection string,
    // credentials included, so the underlying error is never echoed.
    vi.mocked(installCommand).mockRejectedValueOnce(
      new Error('connect ECONNREFUSED'),
    )

    const result = await installEqlStep.run(baseState, provider)

    expect(result.eqlInstalled).toBe(false)
    expect(p.log.error).toHaveBeenCalledWith(
      'EQL install failed — check your database connection and try again.',
    )
  })
})
