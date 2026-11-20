/**
 * Pins that `stash encrypt backfill` refuses a bad `--chunk-size` BEFORE it
 * does anything else.
 *
 * The order matters as much as the refusal. The handler loads the stash
 * config, loads the user's encryption client (jiti, credentials), opens a
 * pg pool, and runs the dual-write gate — which RECORDS its acceptance —
 * before the engine ever sees the chunk size. A `NaN` that was only caught
 * at `LIMIT $n` had already paid for all of that and left a `dual_writing`
 * event behind. So each test asserts the exit AND that none of those steps
 * ran.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

const poolCtor = vi.hoisted(() => vi.fn())
vi.mock('pg', () => ({
  default: {
    Pool: class {
      constructor(config: unknown) {
        poolCtor(config)
      }
      connect = vi.fn(async () => {
        throw new Error('the pool must never be reached')
      })
      end = vi.fn(async () => {})
    },
  },
}))

// Only `installMigrationsSchema` and `runBackfill` need to be observable;
// everything else stays real so a renamed export fails loudly.
const migrateMocks = vi.hoisted(() => ({
  installMigrationsSchema: vi.fn(async () => {}),
  runBackfill: vi.fn(async () => {
    throw new Error('the engine must never be reached')
  }),
}))
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  ...migrateMocks,
}))

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    step: vi.fn(),
  },
}))

const loadStashConfig = vi.hoisted(() =>
  vi.fn(async () => ({ databaseUrl: 'postgres://test' })),
)
vi.mock('@/config/index.js', () => ({ loadStashConfig }))

const loadEncryptionContext = vi.hoisted(() =>
  vi.fn(async () => ({ client: {}, tables: new Map() })),
)
vi.mock('../context.js', () => ({
  loadEncryptionContext,
  requireTable: vi.fn(),
}))

vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))

import * as p from '@clack/prompts'
import { backfillCommand } from '../backfill.js'

/**
 * `process.exit` must THROW here, not return: the real one never returns,
 * and the handler's control flow relies on that. A no-op stub would let the
 * run continue past the guard and fail the "nothing else ran" assertions for
 * the wrong reason.
 */
function spyExit() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`exit ${code}`)
  }) as never)
}

describe('encrypt backfill — --chunk-size validation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it.each([
    ['the NaN that `--chunk-size abc` coerces to', Number('abc')],
    ['zero', 0],
    ['a negative', -5],
    ['a fraction', 1.5],
  ])(
    'rejects %s with exit code 1 before touching anything',
    async (_, chunkSize) => {
      const exitSpy = spyExit()

      await expect(
        backfillCommand({ table: 'users', column: 'email', chunkSize }),
      ).rejects.toThrow('exit 1')

      expect(p.log.error).toHaveBeenCalledWith(
        expect.stringContaining('--chunk-size must be a positive whole number'),
      )
      // Nothing paid for, nothing recorded.
      expect(loadStashConfig).not.toHaveBeenCalled()
      expect(loadEncryptionContext).not.toHaveBeenCalled()
      expect(poolCtor).not.toHaveBeenCalled()
      expect(migrateMocks.installMigrationsSchema).not.toHaveBeenCalled()
      expect(migrateMocks.runBackfill).not.toHaveBeenCalled()

      exitSpy.mockRestore()
    },
  )

  it('quotes the offending value so the typo is recognisable', async () => {
    const exitSpy = spyExit()

    await expect(
      backfillCommand({ table: 'users', column: 'email', chunkSize: 0 }),
    ).rejects.toThrow('exit 1')

    expect(p.log.error).toHaveBeenCalledWith(expect.stringContaining('(got 0)'))
    exitSpy.mockRestore()
  })

  it('lets a valid chunk size through to the rest of the command', async () => {
    const exitSpy = spyExit()

    // Past the guard, the first thing the handler does is load the config;
    // reaching it proves the guard accepted the value. The pool's `connect`
    // then throws, which the handler reports and exits on — that path is not
    // under test here, only that the guard did not fire.
    await expect(
      backfillCommand({ table: 'users', column: 'email', chunkSize: 250 }),
    ).rejects.toThrow('exit 1')

    expect(p.log.error).not.toHaveBeenCalledWith(
      expect.stringContaining('--chunk-size'),
    )
    expect(loadStashConfig).toHaveBeenCalledTimes(1)
    expect(loadEncryptionContext).toHaveBeenCalledTimes(1)
    expect(poolCtor).toHaveBeenCalledTimes(1)
    exitSpy.mockRestore()
  })

  it('applies the default when the flag is absent', async () => {
    const exitSpy = spyExit()

    await expect(
      backfillCommand({ table: 'users', column: 'email' }),
    ).rejects.toThrow('exit 1')

    expect(p.log.error).not.toHaveBeenCalledWith(
      expect.stringContaining('--chunk-size'),
    )
    expect(loadStashConfig).toHaveBeenCalledTimes(1)
    exitSpy.mockRestore()
  })
})
