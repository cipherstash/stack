import { beforeEach, describe, expect, it, vi } from 'vitest'
import { messages } from '../../../../messages.js'
import type { InitProvider, InitState } from '../../types.js'

// Mock the auth strategy seam (extracted in src/auth/strategy.ts) so the
// authenticate step has a single, well-typed boundary to mock instead of the
// NAPI default-export from `@cipherstash/auth`. Strategy.ts itself is
// covered by `src/auth/__tests__/strategy.test.ts`.
const strategy = vi.hoisted(() => ({
  resolveExistingAuth: vi.fn(),
}))
vi.mock('../../../../auth/strategy.js', () => ({
  resolveExistingAuth: strategy.resolveExistingAuth,
  getAuthStrategy: vi.fn(),
}))

const innerAuth = vi.hoisted(() => ({
  selectRegion: vi.fn(),
  login: vi.fn(),
  bindDevice: vi.fn(),
}))
vi.mock('../../../auth/login.js', () => ({
  selectRegion: innerAuth.selectRegion,
  login: innerAuth.login,
  bindDevice: innerAuth.bindDevice,
  regions: [
    { value: 'us-east-1.aws', label: 'us-east-1 (Virginia, USA)' },
    {
      value: 'ap-southeast-2.aws',
      label: 'ap-southeast-2 (Sydney, Australia)',
    },
  ],
}))

const clack = vi.hoisted(() => ({
  log: { success: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))
vi.mock('@clack/prompts', () => ({
  log: clack.log,
}))

const { authenticateStep } = await import('../authenticate.js')

const provider: InitProvider = {
  name: 'drizzle',
  introMessage: 'irrelevant',
  getNextSteps: () => [],
}

describe('authenticateStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('logs the workspace and skips the device-code flow when already authenticated', async () => {
    strategy.resolveExistingAuth.mockResolvedValueOnce({
      workspace: 'WS_TEST',
      regionLabel: 'ap-southeast-2 (Sydney, Australia)',
    })

    const state: InitState = {}
    const next = await authenticateStep.run(state, provider)

    expect(clack.log.success).toHaveBeenCalledWith(
      `${messages.auth.usingWorkspace}WS_TEST (ap-southeast-2 (Sydney, Australia))`,
    )
    expect(innerAuth.selectRegion).not.toHaveBeenCalled()
    expect(innerAuth.login).not.toHaveBeenCalled()
    expect(innerAuth.bindDevice).not.toHaveBeenCalled()
    expect(next).toEqual({ authenticated: true })
  })

  it('falls through to selectRegion → login → bindDevice when not authenticated', async () => {
    strategy.resolveExistingAuth.mockResolvedValueOnce(undefined)
    innerAuth.selectRegion.mockResolvedValueOnce('ap-southeast-2.aws')
    innerAuth.login.mockResolvedValueOnce(undefined)
    innerAuth.bindDevice.mockResolvedValueOnce(undefined)

    const next = await authenticateStep.run({}, provider)

    expect(innerAuth.selectRegion).toHaveBeenCalledTimes(1)
    expect(innerAuth.login).toHaveBeenCalledWith(
      'ap-southeast-2.aws',
      'drizzle',
    )
    expect(innerAuth.bindDevice).toHaveBeenCalledTimes(1)
    expect(next).toEqual({ authenticated: true })
    expect(clack.log.success).not.toHaveBeenCalled()
  })

  it('preserves existing state fields on the authenticated path', async () => {
    strategy.resolveExistingAuth.mockResolvedValueOnce({
      workspace: 'WS_TEST',
      regionLabel: 'unknown',
    })

    const next = await authenticateStep.run(
      { clientFilePath: '/tmp/x.ts' },
      provider,
    )

    expect(next).toEqual({
      clientFilePath: '/tmp/x.ts',
      authenticated: true,
    })
  })
})
