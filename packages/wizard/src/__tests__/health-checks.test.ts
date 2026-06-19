import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Mock constants before importing the module under test
vi.mock('../lib/constants.js', () => ({
  GATEWAY_URL: 'http://localhost:8787',
  HEALTH_CHECK_TIMEOUT_MS: 5_000,
}))

import { checkReadiness } from '../health-checks/index.js'

describe('checkReadiness (unit)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns "ready" when all services are up', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 200 }))
    expect(await checkReadiness()).toBe('ready')
  })

  it('returns "not_ready" when gateway is down', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as Request).url
      if (url.includes('localhost:8787')) {
        throw new Error('Connection refused')
      }
      return new Response(null, { status: 200 })
    })
    expect(await checkReadiness()).toBe('not_ready')
  })

  it('returns "ready_with_warnings" when npm is degraded but gateway is up', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as Request).url
      if (url.includes('npmjs')) {
        return new Response(null, { status: 503 })
      }
      return new Response(null, { status: 200 })
    })
    expect(await checkReadiness()).toBe('ready_with_warnings')
  })
})

describe('checkReadiness (integration against local gateway)', () => {
  let gatewayAvailable = false

  beforeEach(async () => {
    // Check if local gateway is actually running
    try {
      const res = await fetch('http://localhost:8787/health', {
        method: 'HEAD',
        signal: AbortSignal.timeout(2_000),
      })
      gatewayAvailable = res.ok
    } catch {
      gatewayAvailable = false
    }
  })

  it.skipIf(() => !gatewayAvailable)(
    'returns "ready" or "ready_with_warnings" when local gateway is running',
    async () => {
      const result = await checkReadiness()
      expect(['ready', 'ready_with_warnings']).toContain(result)
    },
  )
})
