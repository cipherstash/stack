import * as p from '@clack/prompts'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '../../../cli/exit.js'
import { messages } from '../../../messages.js'
import type { InitState } from '../types.js'

// `--region` is the non-interactive escape hatch for `stash init`; it must land
// on `state.regionFlag` before the authenticate step runs (that step calls
// `resolveRegion({ regionFlag: state.regionFlag })`). Mock every init step so
// the pipeline is inert and observable — `authenticateStep.run` is the spy we
// assert on; the rest just pass state through. Also keeps native-loading steps
// (`authenticate`, `install-deps`) out of the fast suite.
const authRun = vi.hoisted(() => vi.fn(async (state: InitState) => state))
const passthrough = { run: async (s: InitState) => s }
// Controllable so the honest-summary tests can vary whether EQL installed.
const eqlRun = vi.hoisted(() =>
  vi.fn(async (s: InitState) => ({ ...s, eqlInstalled: true })),
)

vi.mock('../steps/authenticate.js', () => ({
  authenticateStep: { id: 'authenticate', name: 'Authenticate', run: authRun },
}))
vi.mock('../steps/resolve-database.js', () => ({
  resolveDatabaseStep: { id: 'resolve-database', ...passthrough },
}))
vi.mock('../steps/resolve-proxy-choice.js', () => ({
  resolveProxyChoiceStep: { id: 'resolve-proxy-choice', ...passthrough },
}))
vi.mock('../steps/build-schema.js', () => ({
  buildSchemaStep: { id: 'build-schema', ...passthrough },
}))
vi.mock('../steps/install-deps.js', () => ({
  installDepsStep: { id: 'install-deps', ...passthrough },
}))
vi.mock('../steps/install-eql.js', () => ({
  // A successful init installs EQL — the default mark keeps the honest-summary
  // gate (`eqlPending` → exit 1) happy for the region-threading runs. The
  // honest-summary tests override `eqlRun` per case.
  installEqlStep: { id: 'install-eql', run: eqlRun },
}))
vi.mock('../steps/gather-context.js', () => ({
  gatherContextStep: { id: 'gather-context', ...passthrough },
}))
// `initCommand` may chain into `stash plan`; keep it inert (never reached in the
// non-TTY test env, but mocked so its module graph never loads).
vi.mock('../../plan/index.js', () => ({ planCommand: vi.fn(async () => {}) }))
vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  confirm: vi.fn(),
  isCancel: vi.fn(() => false),
  cancel: vi.fn(),
  log: { info: vi.fn(), success: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

const { initCommand } = await import('../index.js')

beforeEach(() => {
  vi.clearAllMocks()
})

describe('initCommand — region threading', () => {
  it('seeds state.regionFlag from values.region before authenticate runs', async () => {
    await initCommand({}, { region: 'us-east-1' })

    expect(authRun).toHaveBeenCalledTimes(1)
    // The authenticate step (first in the pipeline) must see the region.
    expect(authRun).toHaveBeenCalledWith(
      expect.objectContaining({ regionFlag: 'us-east-1' }),
      expect.anything(),
    )
  })

  it('leaves regionFlag unset when --region is absent', async () => {
    await initCommand({}, {})

    expect(authRun).toHaveBeenCalledTimes(1)
    const [stateArg] = authRun.mock.calls[0]
    expect(stateArg.regionFlag).toBeUndefined()
  })
})

describe('initCommand — honest summary', () => {
  it('exits non-zero and reports "Setup incomplete" when EQL was not installed', async () => {
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      eqlInstalled: false,
    }))

    await expect(initCommand({}, {})).rejects.toBeInstanceOf(CliExit)
    // The summary titles the run as incomplete, and the EQL fix is surfaced.
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.any(String),
      messages.init.setupIncomplete,
    )
    expect(vi.mocked(p.log.error)).toHaveBeenCalledWith(
      expect.stringContaining(messages.init.eqlNotInstalled),
    )
  })

  it('completes (no throw) when EQL was not installed but the integration is prisma-next', async () => {
    // Prisma Next installs EQL via `migration apply`, so eqlInstalled=false is
    // expected there and must NOT be treated as an incomplete setup.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'prisma-next',
      eqlInstalled: false,
    }))

    await expect(initCommand({}, {})).resolves.toBeUndefined()
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.any(String),
      'Setup complete',
    )
  })

  it('reports a generated Drizzle migration honestly — not installed, not incomplete', async () => {
    // Differential review (PR #687): the Drizzle flow GENERATES an EQL
    // migration; `installEqlStep` returns eqlMigrationPending (not
    // eqlInstalled). The summary must neither claim "✓ EQL extension
    // installed" nor hard-fail as "Setup incomplete" — it should say a
    // migration was generated and point at `drizzle-kit migrate`, then exit 0.
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      integration: 'drizzle',
      eqlInstalled: false,
      eqlMigrationPending: true,
    }))

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    const summary = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Setup complete')
    expect(summary).toBeDefined()
    const body = summary?.[0] as string
    expect(body).toContain('EQL migration generated')
    expect(body).toContain('drizzle-kit migrate')
    expect(body).not.toContain('✓ EQL extension installed')
  })

  it('summary says "kept (existing file)" when an existing client is kept', async () => {
    // The three-way encryption-client checkmark fork was untested — the keep
    // path (`build-schema` sets clientFilePath + schemaGenerated: false) now
    // produces a different string with nothing locking it. This fails against
    // the pre-change code, which always claimed "scaffolded".
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      eqlInstalled: true,
      clientFilePath: './src/encryption/index.ts',
      schemaGenerated: false,
    }))

    await initCommand({}, {})
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.stringContaining('✓ Encryption client kept (existing file)'),
      'Setup complete',
    )
  })

  it('summary says "scaffolded" when a placeholder was written', async () => {
    eqlRun.mockImplementationOnce(async (s: InitState) => ({
      ...s,
      eqlInstalled: true,
      clientFilePath: './src/encryption/index.ts',
      schemaGenerated: true,
    }))

    await initCommand({}, {})
    expect(vi.mocked(p.note)).toHaveBeenCalledWith(
      expect.stringContaining('✓ Encryption client scaffolded'),
      'Setup complete',
    )
  })
})

describe('initCommand — CI detection on the `stash plan` chain offer', () => {
  // Regression: this gate was `process.stdout.isTTY`, which consulted CI not
  // at all. A CI runner with an allocated TTY reached the confirm and blocked
  // on /dev/tty forever — a hang, not an error. It also asked about the wrong
  // stream: a redirected stdin still hangs the prompt. Now `isInteractive()`
  // (stdin + isCiEnv, which accepts 1/true in any case).
  const originalStdinIsTTY = process.stdin.isTTY
  const originalStdoutIsTTY = process.stdout.isTTY

  // Force BOTH streams. A CI runner that allocates a TTY has stdin *and*
  // stdout as TTYs — that is the configuration this gate used to hang in, and
  // setting stdin alone would let the old `process.stdout.isTTY` gate pass
  // these tests for the wrong reason (vitest's own stdout is not a TTY).
  beforeEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: true,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: true,
      configurable: true,
    })
  })

  afterEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: originalStdinIsTTY,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: originalStdoutIsTTY,
      configurable: true,
    })
    vi.unstubAllEnvs()
  })

  for (const ciValue of ['1', 'TRUE', 'true']) {
    it(`skips the chain offer under CI=${ciValue} even with a TTY`, async () => {
      vi.stubEnv('CI', ciValue)

      await expect(initCommand({}, {})).resolves.toBeUndefined()

      // Non-interactive must skip the offer, not fail: init still completes,
      // and steers the user at `plan --target` instead of blocking.
      expect(vi.mocked(p.confirm)).not.toHaveBeenCalled()
      expect(vi.mocked(p.outro)).toHaveBeenCalledWith(
        expect.stringContaining('--target'),
      )
    })
  }

  it('offers the chain when CI is unset and stdin is a TTY', async () => {
    vi.stubEnv('CI', '')
    vi.mocked(p.confirm).mockResolvedValueOnce(false)

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    expect(vi.mocked(p.confirm)).toHaveBeenCalledTimes(1)
  })

  it('skips the chain offer when stdin is redirected even if stdout is a TTY', async () => {
    // The gate keys off stdin, not stdout: `stash init < /dev/null` from a
    // terminal (stdin piped, stdout still a TTY) must not reach the confirm.
    // Reinstating `process.stdout.isTTY` would keep the CI loop above green,
    // so only this stdin/stdout split pins the correct stream.
    vi.stubEnv('CI', '')
    Object.defineProperty(process.stdin, 'isTTY', {
      value: false,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: true,
      configurable: true,
    })

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    expect(vi.mocked(p.confirm)).not.toHaveBeenCalled()
    expect(vi.mocked(p.outro)).toHaveBeenCalledWith(
      expect.stringContaining('--target'),
    )
  })

  it('chains into `stash plan` when the offer is accepted', async () => {
    // The accept arm (outro + planCommand() + early return) is what the gate
    // change made reachable; the only other confirm test resolves `false`.
    vi.stubEnv('CI', '')
    vi.mocked(p.confirm).mockResolvedValueOnce(true)
    const { planCommand } = await import('../../plan/index.js')

    await expect(initCommand({}, {})).resolves.toBeUndefined()

    expect(vi.mocked(planCommand)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(p.outro)).toHaveBeenCalledWith(
      expect.stringContaining('handing off to `stash plan`'),
    )
    // The accept path returns early — it must not also print the --target hint.
    expect(vi.mocked(p.outro)).not.toHaveBeenCalledWith(
      expect.stringContaining('--target'),
    )
  })
})
