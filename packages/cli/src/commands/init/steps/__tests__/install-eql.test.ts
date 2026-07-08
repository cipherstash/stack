import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

// installCommand is the unit under test's collaborator — mock it so we assert
// what init asks for without touching a database.
vi.mock('../../../db/install.js', () => ({ installCommand: vi.fn() }))
// `stash` must appear installed so the precondition guard doesn't short-circuit.
vi.mock('../../utils.js', () => ({ isPackageInstalled: vi.fn(() => true) }))
// Auto-approve the "install EQL now?" prompt; no-op the rest of clack.
vi.mock('@clack/prompts', () => ({
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: { info: vi.fn(), error: vi.fn(), success: vi.fn(), warn: vi.fn() },
  note: vi.fn(),
}))

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
})
