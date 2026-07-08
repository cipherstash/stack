import { beforeEach, describe, expect, it, vi } from 'vitest'

// Mock the two seams `authCommand` forwards into. region.js and login.js are
// replaced so we can assert exactly what the `login` subcommand hands them —
// the E2E suite only covers the negative resolveRegion paths (which fail before
// any network I/O), so the success-path forwarding is otherwise untested.
const regionMock = vi.hoisted(() => ({
  resolveRegion: vi.fn(async () => 'us-east-1.aws'),
  failRegion: vi.fn(() => {
    throw new Error('failRegion')
  }),
  regionList: vi.fn(() => [{ slug: 'us-east-1', label: 'us-east-1 (…)' }]),
}))
vi.mock('../region.js', () => regionMock)

const loginMock = vi.hoisted(() => ({
  login: vi.fn(async () => {}),
  bindDevice: vi.fn(async () => {}),
}))
vi.mock('../login.js', () => loginMock)

const { authCommand } = await import('../index.js')

beforeEach(() => {
  vi.clearAllMocks()
})

describe('authCommand login — option forwarding', () => {
  it('forwards values.region + json into resolveRegion and login/bindDevice', async () => {
    await authCommand(['login'], {}, { region: 'us-east-1' })

    expect(regionMock.resolveRegion).toHaveBeenCalledWith({
      regionFlag: 'us-east-1',
      json: false,
    })
    // Resolved region + referrer (none) + open true (not json, no --no-open).
    expect(loginMock.login).toHaveBeenCalledWith('us-east-1.aws', undefined, {
      json: false,
      open: true,
    })
    expect(loginMock.bindDevice).toHaveBeenCalledWith({ json: false })
  })

  it('threads --json through and suppresses the browser open', async () => {
    await authCommand(['login'], { json: true }, {})

    expect(regionMock.resolveRegion).toHaveBeenCalledWith({
      regionFlag: undefined,
      json: true,
    })
    // json ⇒ open must be false regardless of --no-open.
    expect(loginMock.login).toHaveBeenCalledWith('us-east-1.aws', undefined, {
      json: true,
      open: false,
    })
    expect(loginMock.bindDevice).toHaveBeenCalledWith({ json: true })
  })

  it('honours --no-open on the interactive path (open: false)', async () => {
    await authCommand(['login'], { 'no-open': true }, {})

    expect(loginMock.login).toHaveBeenCalledWith('us-east-1.aws', undefined, {
      json: false,
      open: false,
    })
  })

  it('derives the referrer from --supabase / --drizzle', async () => {
    await authCommand(['login'], { drizzle: true, supabase: true }, {})

    expect(loginMock.login).toHaveBeenCalledWith(
      'us-east-1.aws',
      'drizzle-supabase',
      expect.objectContaining({ json: false }),
    )
  })

  it('fails fast on a valueless --region without calling login', async () => {
    // `--region` with no value booleanises into flags; guard must fire first.
    await expect(authCommand(['login'], { region: true }, {})).rejects.toThrow(
      'failRegion',
    )

    expect(regionMock.failRegion).toHaveBeenCalledWith(
      false,
      'region_invalid',
      expect.any(String),
    )
    expect(regionMock.resolveRegion).not.toHaveBeenCalled()
    expect(loginMock.login).not.toHaveBeenCalled()
  })
})
