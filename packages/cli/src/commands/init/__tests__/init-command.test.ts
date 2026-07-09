import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitState } from '../types.js'

// `--region` is the non-interactive escape hatch for `stash init`; it must land
// on `state.regionFlag` before the authenticate step runs (that step calls
// `resolveRegion({ regionFlag: state.regionFlag })`). Mock every init step so
// the pipeline is inert and observable — `authenticateStep.run` is the spy we
// assert on; the rest just pass state through. Also keeps native-loading steps
// (`authenticate`, `install-deps`) out of the fast suite.
const authRun = vi.hoisted(() => vi.fn(async (state: InitState) => state))
const passthrough = { run: async (s: InitState) => s }

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
  installEqlStep: { id: 'install-eql', ...passthrough },
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
