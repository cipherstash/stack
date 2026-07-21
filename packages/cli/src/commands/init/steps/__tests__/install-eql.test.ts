import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

// installCommand is the unit under test's collaborator — mock it so we assert
// what init asks for without touching a database.
vi.mock('../../../db/install.js', () => ({ installCommand: vi.fn() }))
// The Drizzle branch generates a v3 migration instead of calling installCommand.
vi.mock('../../../eql/migration.js', () => ({
  eqlMigrationCommand: vi.fn(async () => undefined),
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
import { isInteractive } from '../../../../config/tty.js'
import { ensureEncryptionClient } from '../../../db/client-scaffold.js'
import { offerStashConfig } from '../../../db/config-scaffold.js'
import { installCommand } from '../../../db/install.js'
import { eqlMigrationCommand } from '../../../eql/migration.js'
import { installEqlStep } from '../install-eql.js'

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

    // `undefined` means "take the v3 default" in resolveEqlVersion.
    expect(
      vi.mocked(installCommand).mock.calls[0][0].eqlVersion,
    ).toBeUndefined()
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
})
