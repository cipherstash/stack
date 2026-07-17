import * as p from '@clack/prompts'
import { beforeEach, describe, expect, it, vi } from 'vitest'
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
})
