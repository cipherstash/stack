import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { messages } from '../../../messages.js'

// env/index.ts imports the native `@cipherstash/auth` binary — replace it
// before load so the unit suite stays native-free (same pattern as
// `auth/__tests__/login.test.ts`). 0.41+ Result envelopes throughout.
const authMock = vi.hoisted(() => ({
  DeviceSessionStrategy: { fromProfile: vi.fn() },
}))
vi.mock('@cipherstash/auth', () => ({ default: authMock }))

const clack = vi.hoisted(() => {
  const spinnerInstance = { start: vi.fn(), stop: vi.fn() }
  return {
    spinnerInstance,
    intro: vi.fn(),
    outro: vi.fn(),
    cancel: vi.fn(),
    spinner: vi.fn(() => spinnerInstance),
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
    text: vi.fn(),
    confirm: vi.fn(),
    isCancel: vi.fn(() => false),
  }
})
vi.mock('@clack/prompts', () => clack)

// Interactivity is env-dependent; pin it per test.
const tty = vi.hoisted(() => ({ isInteractive: vi.fn(() => false) }))
vi.mock('../../../config/tty.js', () => tty)

// Keep the runner deterministic (`npx stash`) regardless of the dev machine.
vi.mock('../../init/utils.js', () => ({
  detectPackageManager: () => 'npm',
  runnerCommand: () => 'npx ',
}))

const { envCommand } = await import('../index.js')

/** Sentinel thrown by the stubbed `process.exit` so tests can assert on it. */
class ExitSignal extends Error {
  constructor(readonly code: number | undefined) {
    super(`exit ${code}`)
  }
}

/** A happy-path device session: fromProfile → getToken → token data. */
function stubSession(over: Record<string, unknown> = {}) {
  authMock.DeviceSessionStrategy.fromProfile.mockReturnValue({
    data: {
      getToken: vi.fn(async () => ({
        data: {
          token: 'test-bearer-token',
          subject: 'CS|user',
          workspaceId: 'WS123',
          issuer: 'https://cts.test/',
          services: { zerokms: 'https://zkms.test/' },
          ...over,
        },
      })),
    },
  })
}

/**
 * Route the three HTTP calls by URL. Returns the fetch spy. Bodies mirror the
 * real cts-web / zerokms-protocol wire shapes.
 */
function stubFetch(
  overrides: Partial<
    Record<'workspaces' | 'client' | 'accessKey', Response>
  > = {},
) {
  const routes: Array<{ match: string; response: () => Response }> = [
    {
      match: '/api/workspaces',
      response: () =>
        overrides.workspaces ??
        Response.json([
          {
            id: 'OTHER',
            name: 'other',
            role: 'member',
            region: 'us-east-1.aws',
            org_id: 'o',
          },
          {
            id: 'WS123',
            name: 'mine',
            role: 'admin',
            region: 'ap-southeast-2.aws',
            org_id: 'o',
          },
        ]),
    },
    {
      match: '/create-client',
      response: () =>
        overrides.client ??
        // client_key: base64 of bytes 00 01 02 03 → hex "00010203"
        Response.json({
          id: 'client-uuid-1',
          dataset_id: 'ks-uuid',
          name: 'my-app-prod',
          description: 'd',
          client_key: 'AAECAw==',
        }),
    },
    {
      match: '/api/access-keys',
      response: () =>
        overrides.accessKey ??
        Response.json(
          { accessKey: 'CSAKTkeyid.keysecret', role: 'member' },
          { status: 201 },
        ),
    },
  ]
  const fetchSpy = vi.fn(async (url: string | URL) => {
    const href = String(url)
    const route = routes.find((r) => href.includes(r.match))
    if (!route) throw new Error(`unexpected fetch: ${href}`)
    return route.response()
  })
  vi.stubGlobal('fetch', fetchSpy)
  return fetchSpy
}

let exitSpy: ReturnType<typeof vi.spyOn>
let logSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new ExitSignal(code)
  }) as never)
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  authMock.DeviceSessionStrategy.fromProfile.mockReset()
  tty.isInteractive.mockReturnValue(false)
})

/** Every console.log line joined — the command's full stdout. */
function stdout(): string {
  return logSpy.mock.calls.map((c) => c.join(' ')).join('\n')
}

describe('envCommand — name resolution', () => {
  it('fails non-interactively without --name, before touching the profile', async () => {
    await expect(envCommand({})).rejects.toThrow(ExitSignal)
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining(messages.env.missingName),
    )
    // The failure must be reachable with no profile and no network.
    expect(authMock.DeviceSessionStrategy.fromProfile).not.toHaveBeenCalled()
  })

  it('emits the error envelope on the --json stream', async () => {
    await expect(envCommand({ json: true })).rejects.toThrow(ExitSignal)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({ status: 'error', code: 'missing_name' })
  })
})

describe('envCommand — happy path', () => {
  it('mints credentials and prints the four env vars', async () => {
    stubSession()
    const fetchSpy = stubFetch()

    await envCommand({ name: 'my-app-prod' })

    const block = stdout()
    expect(block).toContain('CS_WORKSPACE_CRN=crn:ap-southeast-2.aws:WS123')
    expect(block).toContain('CS_CLIENT_ID=client-uuid-1')
    // Hex-transcoded from base64 AAECAw==
    expect(block).toContain('CS_CLIENT_KEY=00010203')
    expect(block).toContain('CS_CLIENT_ACCESS_KEY=CSAKTkeyid.keysecret')
    expect(block).toContain('Do not commit')
    // The bearer token must never reach stdout.
    expect(block).not.toContain('test-bearer-token')

    // Ordering contract: client BEFORE access key (partial failure leaves an
    // inert client, never an unaccounted-for live credential).
    const urls = fetchSpy.mock.calls.map((c) => String(c[0]))
    expect(urls.findIndex((u) => u.includes('/create-client'))).toBeLessThan(
      urls.findIndex((u) => u.includes('/api/access-keys')),
    )

    // Wire details: bearer auth everywhere; role omitted (server defaults to
    // member); trailing slashes normalised (no `//` in paths).
    for (const [url, init] of fetchSpy.mock.calls as [string, RequestInit][]) {
      expect((init.headers as Record<string, string>).authorization).toBe(
        'Bearer test-bearer-token',
      )
      expect(String(url)).not.toMatch(/[^:]\/\//)
    }
    const accessKeyCall = fetchSpy.mock.calls.find((c) =>
      String(c[0]).includes('/api/access-keys'),
    ) as [string, RequestInit]
    const body = JSON.parse(String(accessKeyCall[1].body))
    expect(body).toEqual({ keyName: 'my-app-prod', workspaceId: 'WS123' })
    expect(body).not.toHaveProperty('role')
  })

  it('emits a single minted object in --json mode', async () => {
    stubSession()
    stubFetch()

    await envCommand({ name: 'edge-dev', json: true })

    expect(logSpy).toHaveBeenCalledTimes(1)
    const event = JSON.parse(logSpy.mock.calls[0][0] as string)
    expect(event).toEqual({
      status: 'minted',
      keyName: 'edge-dev',
      workspaceCrn: 'crn:ap-southeast-2.aws:WS123',
      clientId: 'client-uuid-1',
      clientKey: '00010203',
      accessKey: 'CSAKTkeyid.keysecret',
    })
  })
})

describe('envCommand — failure modes', () => {
  it('reports a missing login with an auth hint', async () => {
    authMock.DeviceSessionStrategy.fromProfile.mockReturnValue({
      failure: { type: 'not_authenticated', error: new Error('no auth.json') },
    })
    stubFetch()

    await expect(envCommand({ name: 'x' })).rejects.toThrow(ExitSignal)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('Not logged in'),
    )
    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('npx stash auth login'),
    )
  })

  it('maps a 403 on access-key creation to the admin-role message, naming the leftover client', async () => {
    stubSession()
    stubFetch({ accessKey: new Response('forbidden', { status: 403 }) })

    await expect(envCommand({ name: 'my-app-prod' })).rejects.toThrow(
      ExitSignal,
    )
    const message = String(clack.log.error.mock.calls.at(-1)?.[0])
    expect(message).toContain('admin')
    expect(message).toContain("ZeroKMS client 'my-app-prod'")
  })

  it('suggests --name on a duplicate-name rejection', async () => {
    stubSession()
    stubFetch({
      accessKey: new Response('{"error":"Duplicate key error"}', {
        status: 400,
      }),
    })

    await expect(envCommand({ name: 'taken' })).rejects.toThrow(ExitSignal)
    const message = String(clack.log.error.mock.calls.at(-1)?.[0])
    expect(message).toContain('Duplicate key error')
    expect(message).toContain('--name')
  })

  it('fails when the session workspace is missing from the workspace list', async () => {
    stubSession({ workspaceId: 'GONE' })
    stubFetch()

    await expect(envCommand({ name: 'x' })).rejects.toThrow(ExitSignal)
    expect(String(clack.log.error.mock.calls.at(-1)?.[0])).toContain('GONE')
  })
})

describe('envCommand — --write', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'stash-env-test-'))
    vi.spyOn(process, 'cwd').mockReturnValue(dir)
  })
  afterEach(() => {
    // The file is written 0600; ensure cleanup can always delete it.
    try {
      chmodSync(join(dir, '.env.production.local'), 0o600)
    } catch {}
    rmSync(dir, { recursive: true, force: true })
  })

  it('writes .env.production.local with mode 0600', async () => {
    stubSession()
    stubFetch()

    await envCommand({ name: 'my-app-prod', write: true })

    const target = join(dir, '.env.production.local')
    const content = readFileSync(target, 'utf-8')
    expect(content).toContain('CS_CLIENT_ACCESS_KEY=CSAKTkeyid.keysecret')
    expect(statSync(target).mode & 0o777).toBe(0o600)
    // Nothing printed to stdout on the write path.
    expect(stdout()).not.toContain('CS_CLIENT_ACCESS_KEY')
  })

  it('refuses to overwrite an existing file non-interactively', async () => {
    stubSession()
    stubFetch()
    writeFileSync(join(dir, '.env.production.local'), 'existing')

    await expect(envCommand({ name: 'x', write: true })).rejects.toThrow(
      ExitSignal,
    )
    expect(readFileSync(join(dir, '.env.production.local'), 'utf-8')).toBe(
      'existing',
    )
    expect(String(clack.log.error.mock.calls.at(-1)?.[0])).toContain(
      'refusing to overwrite',
    )
  })
})
