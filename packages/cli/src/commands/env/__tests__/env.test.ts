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
import { CliExit } from '../../../cli/exit.js'
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

/** Run envCommand and return the CliExit it threw (fails if it didn't). */
async function expectExit(
  promise: Promise<void>,
  code: number,
): Promise<CliExit> {
  try {
    await promise
  } catch (err) {
    expect(err).toBeInstanceOf(CliExit)
    expect((err as CliExit).code).toBe(code)
    return err as CliExit
  }
  throw new Error(`expected CliExit(${code}), but the command returned`)
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

let logSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
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

/** The most recent p.log.error message (first arg; second is the stderr chrome opts). */
function lastError(): string {
  return String(clack.log.error.mock.calls.at(-1)?.[0])
}

describe('envCommand — pre-mint argv failures (all credential-free)', () => {
  it('fails non-interactively without --name, before touching the profile', async () => {
    await expectExit(envCommand({}), 1)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining(messages.env.missingName),
      expect.anything(),
    )
    // The failure must be reachable with no profile and no network.
    expect(authMock.DeviceSessionStrategy.fromProfile).not.toHaveBeenCalled()
  })

  it('emits the error envelope on the --json stream', async () => {
    await expectExit(envCommand({ json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({ status: 'error', code: 'missing_name' })
  })

  it('rejects a valueless --name with its own error, not missing_name', async () => {
    await expectExit(envCommand({ nameMissingValue: true, json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({
      status: 'error',
      code: 'name_requires_value',
    })
    expect(authMock.DeviceSessionStrategy.fromProfile).not.toHaveBeenCalled()
  })

  it('rejects a name containing control characters before touching the profile', async () => {
    await expectExit(envCommand({ name: 'bad\nCS_INJECTED=1', json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({ status: 'error', code: 'invalid_name' })
    expect(authMock.DeviceSessionStrategy.fromProfile).not.toHaveBeenCalled()
  })

  it('rejects a stray positional with did-you-mean guidance', async () => {
    await expectExit(envCommand({ unexpectedArg: 'my-app-prod' }), 1)
    const message = lastError()
    expect(message).toContain(messages.env.unexpectedArgument)
    expect(message).toContain('--name my-app-prod')
    expect(authMock.DeviceSessionStrategy.fromProfile).not.toHaveBeenCalled()
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
    // Stdout is pipe-clean: exactly one console.log — the block itself.
    // (All chrome goes through the mocked clack, which routes to stderr.)
    expect(logSpy).toHaveBeenCalledTimes(1)

    // Ordering contract: client BEFORE access key (partial failure leaves an
    // inert client, never an unaccounted-for live credential).
    const urls = fetchSpy.mock.calls.map((c) => String(c[0]))
    expect(urls.findIndex((u) => u.includes('/create-client'))).toBeLessThan(
      urls.findIndex((u) => u.includes('/api/access-keys')),
    )

    // Wire details: bearer auth everywhere; the member role is pinned in the
    // request; trailing slashes normalised (no `//` in paths).
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
    expect(body).toEqual({
      keyName: 'my-app-prod',
      workspaceId: 'WS123',
      role: 'member',
    })
  })

  it('routes all chrome to stderr', async () => {
    stubSession()
    stubFetch()

    await envCommand({ name: 'my-app-prod' })

    const stderrOpts = { output: process.stderr }
    expect(clack.intro).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining(stderrOpts),
    )
    expect(clack.spinner).toHaveBeenCalledWith(
      expect.objectContaining(stderrOpts),
    )
    expect(clack.outro).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining(stderrOpts),
    )
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

    await expectExit(envCommand({ name: 'x' }), 1)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('Not logged in'),
      expect.anything(),
    )
    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('npx stash auth login'),
      expect.anything(),
    )
  })

  it('maps a 403 on access-key creation to the admin-role message, naming the leftover client', async () => {
    stubSession()
    stubFetch({ accessKey: new Response('forbidden', { status: 403 }) })

    await expectExit(envCommand({ name: 'my-app-prod' }), 1)
    const message = lastError()
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

    await expectExit(envCommand({ name: 'taken' }), 1)
    const message = lastError()
    expect(message).toContain('Duplicate key error')
    expect(message).toContain('--name')
  })

  it('maps a request timeout to a clear request_timeout error', async () => {
    stubSession()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new DOMException('The operation timed out.', 'TimeoutError')
      }),
    )

    await expectExit(envCommand({ name: 'x', json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({ status: 'error', code: 'request_timeout' })
    expect(String(event.message)).toContain('cts.test')
  })

  it('maps a connection failure to a network_error naming the host', async () => {
    stubSession()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed', {
          cause: new Error('getaddrinfo ENOTFOUND cts.test'),
        })
      }),
    )

    await expectExit(envCommand({ name: 'x', json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({ status: 'error', code: 'network_error' })
    expect(String(event.message)).toContain('ENOTFOUND')
  })

  it('fails when the session workspace is missing from the workspace list', async () => {
    stubSession({ workspaceId: 'GONE' })
    stubFetch()

    await expectExit(envCommand({ name: 'x' }), 1)
    expect(lastError()).toContain('GONE')
  })
})

describe('envCommand — response validation (nothing minted may print undefined)', () => {
  it('rejects a workspace entry with no region instead of emitting crn:undefined', async () => {
    stubSession()
    stubFetch({
      workspaces: Response.json([{ id: 'WS123', name: 'mine' }]),
    })

    await expectExit(envCommand({ name: 'x', json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({
      status: 'error',
      code: 'unexpected_response',
    })
    expect(String(event.message)).toContain('region')
  })

  it('rejects an access-key response with no accessKey field', async () => {
    stubSession()
    stubFetch({ accessKey: Response.json({ ok: true }, { status: 201 }) })

    await expectExit(envCommand({ name: 'x', json: true }), 1)
    const event = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string)
    expect(event).toMatchObject({
      status: 'error',
      code: 'unexpected_response',
    })
  })

  it('refuses to transcode non-base64 client key material', async () => {
    stubSession()
    stubFetch({
      client: Response.json({ id: 'c1', client_key: 'not!!valid==' }),
    })

    await expectExit(envCommand({ name: 'x' }), 1)
    expect(lastError()).toContain('unexpected encoding')
  })

  it('refuses to emit an access key whose returned role is not member', async () => {
    stubSession()
    stubFetch({
      accessKey: Response.json(
        { accessKey: 'CSAKTid.secret', role: 'admin' },
        { status: 201 },
      ),
    })

    await expectExit(envCommand({ name: 'privileged' }), 1)
    const message = lastError()
    expect(message).toContain("'admin'")
    expect(message).toContain("Revoke 'privileged'")
    // The over-privileged secret itself must not be printed anywhere.
    expect(stdout()).not.toContain('CSAKTid.secret')
  })
})

describe('envCommand — --write', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'stash-env-test-'))
    vi.spyOn(process, 'cwd').mockReturnValue(dir)
  })
  afterEach(() => {
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

  it('honours a custom path passed as the --write value', async () => {
    stubSession()
    stubFetch()

    await envCommand({ name: 'staging', write: '.env.staging.local' })

    const target = join(dir, '.env.staging.local')
    expect(readFileSync(target, 'utf-8')).toContain('CS_CLIENT_ACCESS_KEY=')
    expect(statSync(target).mode & 0o777).toBe(0o600)
  })

  it('re-applies 0600 when overwriting an existing permissive file', async () => {
    stubSession()
    stubFetch()
    const target = join(dir, '.env.production.local')
    writeFileSync(target, 'OLD=1')
    chmodSync(target, 0o644)
    tty.isInteractive.mockReturnValue(true)
    clack.confirm.mockResolvedValue(true)

    await envCommand({ name: 'x', write: true })

    expect(readFileSync(target, 'utf-8')).toContain('CS_CLIENT_ACCESS_KEY=')
    expect(statSync(target).mode & 0o777).toBe(0o600)
  })

  it('refuses an existing file non-interactively BEFORE minting anything', async () => {
    stubSession()
    const fetchSpy = stubFetch()
    writeFileSync(join(dir, '.env.production.local'), 'existing')

    await expectExit(envCommand({ name: 'x', write: true }), 1)
    expect(readFileSync(join(dir, '.env.production.local'), 'utf-8')).toBe(
      'existing',
    )
    expect(lastError()).toContain('refusing to overwrite')
    // The load-bearing bit: the refusal happened with ZERO server state
    // created — no fetch, no client, no orphaned shown-once access key.
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('declining the interactive overwrite aborts BEFORE minting, exit 0', async () => {
    stubSession()
    const fetchSpy = stubFetch()
    writeFileSync(join(dir, '.env.production.local'), 'existing')
    tty.isInteractive.mockReturnValue(true)
    clack.confirm.mockResolvedValue(false)

    await expectExit(envCommand({ name: 'x', write: true }), 0)
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(clack.cancel).toHaveBeenCalledWith(
      expect.stringContaining('nothing was minted'),
      expect.anything(),
    )
  })

  it('--json --write writes the file and emits a secret-free confirmation', async () => {
    stubSession()
    stubFetch()

    await envCommand({ name: 'edge-dev', write: true, json: true })

    const target = join(dir, '.env.production.local')
    expect(readFileSync(target, 'utf-8')).toContain(
      'CS_CLIENT_ACCESS_KEY=CSAKTkeyid.keysecret',
    )
    expect(logSpy).toHaveBeenCalledTimes(1)
    const event = JSON.parse(logSpy.mock.calls[0][0] as string)
    expect(event).toEqual({
      status: 'written',
      path: target,
      keyName: 'edge-dev',
      workspaceCrn: 'crn:ap-southeast-2.aws:WS123',
      clientId: 'client-uuid-1',
    })
    // The secrets live in the 0600 file only — never on the JSON stream.
    const raw = logSpy.mock.calls[0][0] as string
    expect(raw).not.toContain('CSAKTkeyid.keysecret')
    expect(raw).not.toContain('00010203')
  })
})
