import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { messages } from '../../../messages.js'

// region.ts imports `* as p from '@clack/prompts'` (no native `@cipherstash/auth`
// dependency — that's the whole reason the region logic lives in its own
// module). Mock the prompt seam so `selectRegion` is observable and never
// actually blocks on a TTY.
const clack = vi.hoisted(() => ({
  select: vi.fn(),
  isCancel: vi.fn(() => false),
  cancel: vi.fn(),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
}))
vi.mock('@clack/prompts', () => ({
  select: clack.select,
  isCancel: clack.isCancel,
  cancel: clack.cancel,
  log: clack.log,
}))

const {
  normalizeRegion,
  regionList,
  regionSlugs,
  resolveRegion,
  REGION_ENV_VAR,
} = await import('../region.js')

let originalRegionEnv: string | undefined
let originalCi: string | undefined
let originalIsTty: boolean | undefined

function setTty(value: boolean | undefined) {
  Object.defineProperty(process.stdin, 'isTTY', {
    value,
    configurable: true,
  })
}

/** Spy process.exit so the code-under-test unwinds via a throw we can assert on. */
function spyExit() {
  return vi.spyOn(process, 'exit').mockImplementation((() => {
    throw new Error('process.exit')
  }) as never)
}

beforeEach(() => {
  originalRegionEnv = process.env[REGION_ENV_VAR]
  originalCi = process.env.CI
  originalIsTty = process.stdin.isTTY
  // biome-ignore lint/performance/noDelete: `env.X = undefined` stores the string "undefined".
  delete process.env[REGION_ENV_VAR]
  // biome-ignore lint/performance/noDelete: ditto.
  delete process.env.CI
})

afterEach(() => {
  if (originalRegionEnv === undefined) {
    // biome-ignore lint/performance/noDelete: see above.
    delete process.env[REGION_ENV_VAR]
  } else {
    process.env[REGION_ENV_VAR] = originalRegionEnv
  }
  if (originalCi === undefined) {
    // biome-ignore lint/performance/noDelete: see above.
    delete process.env.CI
  } else {
    process.env.CI = originalCi
  }
  setTty(originalIsTty)
  vi.restoreAllMocks()
})

describe('normalizeRegion', () => {
  it('accepts a short slug and returns the canonical .aws form', () => {
    expect(normalizeRegion('us-east-1')).toBe('us-east-1.aws')
  })

  it('accepts the canonical .aws form unchanged', () => {
    expect(normalizeRegion('ap-southeast-2.aws')).toBe('ap-southeast-2.aws')
  })

  it('is case-insensitive and trims whitespace', () => {
    expect(normalizeRegion('  US-East-1  ')).toBe('us-east-1.aws')
  })

  it('returns null for an unknown region', () => {
    expect(normalizeRegion('moon-base-1')).toBeNull()
    expect(normalizeRegion('us-east-9')).toBeNull()
  })

  it('returns null for empty / whitespace input', () => {
    expect(normalizeRegion('')).toBeNull()
    expect(normalizeRegion('   ')).toBeNull()
  })
})

describe('regionSlugs', () => {
  it('lists the short slugs without the .aws suffix', () => {
    const slugs = regionSlugs()
    expect(slugs).toContain('us-east-1')
    expect(slugs).toContain('ap-southeast-2')
    expect(slugs.every((s) => !s.endsWith('.aws'))).toBe(true)
  })
})

describe('regionList', () => {
  it('returns { slug, label } pairs for every region', () => {
    const list = regionList()
    expect(list.length).toBe(regionSlugs().length)
    for (const entry of list) {
      expect(entry.slug).not.toMatch(/\.aws$/)
      // Each slug must normalize back to a real region.
      expect(normalizeRegion(entry.slug)).toBe(`${entry.slug}.aws`)
      // Label is human copy that leads with the slug.
      expect(entry.label.startsWith(entry.slug)).toBe(true)
    }
  })

  it('includes a known region', () => {
    expect(regionList()).toContainEqual({
      slug: 'us-east-1',
      label: 'us-east-1 (Virginia, USA)',
    })
  })
})

describe('resolveRegion — explicit region', () => {
  it('returns the normalized region from the flag and never prompts', async () => {
    await expect(resolveRegion({ regionFlag: 'us-west-2' })).resolves.toBe(
      'us-west-2.aws',
    )
    expect(clack.select).not.toHaveBeenCalled()
  })

  it('reads STASH_REGION when no flag is passed', async () => {
    process.env[REGION_ENV_VAR] = 'eu-west-1'
    await expect(resolveRegion()).resolves.toBe('eu-west-1.aws')
    expect(clack.select).not.toHaveBeenCalled()
  })

  it('prefers the flag over STASH_REGION', async () => {
    process.env[REGION_ENV_VAR] = 'eu-west-1'
    await expect(resolveRegion({ regionFlag: 'us-east-2' })).resolves.toBe(
      'us-east-2.aws',
    )
  })

  it('treats an empty / whitespace flag as absent and falls back to STASH_REGION', async () => {
    process.env[REGION_ENV_VAR] = 'eu-west-1'
    // `--region ""` / `--region "   "` must not shadow the env var — matches
    // the `if (values.region)` guard init uses, so both entry points agree.
    await expect(resolveRegion({ regionFlag: '   ' })).resolves.toBe(
      'eu-west-1.aws',
    )
    expect(clack.select).not.toHaveBeenCalled()
  })

  it('empty flag with no env in a non-TTY context exits 1 (region_required)', async () => {
    setTty(undefined)
    const exitSpy = spyExit()
    await expect(resolveRegion({ regionFlag: '' })).rejects.toThrow(
      'process.exit',
    )
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith(
      messages.auth.regionMissingNonInteractive,
    )
  })

  it('exits 1 with an actionable error on an unknown explicit region', async () => {
    const exitSpy = spyExit()
    await expect(resolveRegion({ regionFlag: 'moon-base-1' })).rejects.toThrow(
      'process.exit',
    )
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith(
      messages.auth.regionInvalid('moon-base-1', regionSlugs()),
    )
  })

  it('emits a JSON error (not clack) on an unknown region in json mode', async () => {
    const exitSpy = spyExit()
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await expect(
      resolveRegion({ regionFlag: 'moon-base-1', json: true }),
    ).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).not.toHaveBeenCalled()
    const payload = JSON.parse(logSpy.mock.calls[0][0] as string)
    expect(payload).toMatchObject({ status: 'error', code: 'region_invalid' })
  })
})

describe('resolveRegion — no explicit region', () => {
  it('prompts interactively when stdin is a TTY and not CI', async () => {
    setTty(true)
    clack.select.mockResolvedValueOnce('us-east-1.aws')
    await expect(resolveRegion()).resolves.toBe('us-east-1.aws')
    expect(clack.select).toHaveBeenCalledTimes(1)
  })

  it('exits 1 (no hang) in a non-TTY context without a region', async () => {
    setTty(undefined)
    const exitSpy = spyExit()
    await expect(resolveRegion()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith(
      messages.auth.regionMissingNonInteractive,
    )
    expect(clack.select).not.toHaveBeenCalled()
  })

  it('exits 1 in a TTY when CI is set (CI is not interactive)', async () => {
    setTty(true)
    process.env.CI = 'true'
    const exitSpy = spyExit()
    await expect(resolveRegion()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.select).not.toHaveBeenCalled()
  })

  it('never prompts in json mode even on a TTY, emitting a JSON error', async () => {
    setTty(true)
    const exitSpy = spyExit()
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await expect(resolveRegion({ json: true })).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.select).not.toHaveBeenCalled()
    const payload = JSON.parse(logSpy.mock.calls[0][0] as string)
    expect(payload).toMatchObject({ status: 'error', code: 'region_required' })
  })
})
