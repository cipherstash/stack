import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

// installCommand is the unit under test's collaborator — mock it so we assert
// what init asks for without touching a database.
vi.mock('../../../db/install.js', () => ({ installCommand: vi.fn() }))
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
import { installCommand } from '../../../db/install.js'
import { installEqlStep } from '../install-eql.js'

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

  it('maps a generated Drizzle migration to eqlMigrationPending, NOT eqlInstalled', async () => {
    // The Drizzle path only WRITES a v2 migration — EQL isn't in the DB until
    // the user runs `drizzle-kit migrate`. `installEqlStep` must carry that
    // distinction through so `initCommand` doesn't claim "EQL installed".
    // This is the seam the differential review flagged (PR #687): the step
    // used to return `eqlInstalled: true` for every non-throwing outcome.
    const drizzleState = {
      integration: 'drizzle',
      databaseUrl: 'postgresql://localhost:5432/app',
    } as unknown as InitState
    vi.mocked(installCommand).mockResolvedValueOnce('migration-generated')

    const result = await installEqlStep.run(drizzleState, {
      name: 'drizzle',
    } as unknown as InitProvider)

    // Pinned to v2 for the Drizzle migration path (v3 rejects --drizzle).
    expect(vi.mocked(installCommand).mock.calls[0][0].eqlVersion).toBe('2')
    expect(result.eqlInstalled).toBe(false)
    expect(result.eqlMigrationPending).toBe(true)
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
