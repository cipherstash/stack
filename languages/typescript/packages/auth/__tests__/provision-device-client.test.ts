import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MockCtsServer } from './helpers/mock-cts-server'
import { saveTestToken } from './helpers/test-fixtures'

const { bindClientDevice } = require('../index.js') as typeof import('../index')

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_WORKSPACE_ID = 'ZVATKW3VHMFG27DY'

let server: MockCtsServer
let profileDir: string
let savedConfigPath: string | undefined

function freshProfileDir(): string {
  return mkdtempSync(join(tmpdir(), 'cs-auth-test-'))
}

function workspaceDir(): string {
  return join(profileDir, 'workspaces', TEST_WORKSPACE_ID)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('provision device client (TypeScript / vitest)', () => {
  beforeEach(async () => {
    server = await MockCtsServer.start()
    profileDir = freshProfileDir()
    // Production `bindClientDevice()` resolves its profile dir from
    // CS_CONFIG_PATH (ProfileStore::resolve), so point it at the temp dir.
    savedConfigPath = process.env.CS_CONFIG_PATH
    process.env.CS_CONFIG_PATH = profileDir
  })

  afterEach(async () => {
    if (savedConfigPath === undefined) {
      delete process.env.CS_CONFIG_PATH
    } else {
      process.env.CS_CONFIG_PATH = savedConfigPath
    }
    await server.close()
  })

  // A profile token's ZeroKMS claim is unverified, so provisioning only
  // sends the bearer to a CipherStash-hosted ZeroKMS. This mock server is not
  // one, so the binding cannot reach it: the success and 409 paths are
  // covered by stack-auth's Rust tests through its transport seam, and here
  // the binding must refuse before any request leaves.
  it('refuses a token naming a ZeroKMS outside CipherStash, before sending it', async () => {
    server.mockCreateClientEndpoint()
    saveTestToken(profileDir, server.baseUrl)

    const r = await bindClientDevice()

    expect(r.failure?.type).toBe('INVALID_TOKEN')
    expect(r.failure?.error).toBeInstanceOf(Error)
    expect(server.requestCount).toBe(0)
    expect(existsSync(join(workspaceDir(), 'secretkey.json'))).toBe(false)
  })

  it('is a no-op when secretkey.json already exists', async () => {
    // No mock endpoints needed — should short-circuit before any HTTP call.
    saveTestToken(profileDir, server.baseUrl)

    // Pre-create secretkey.json in the workspace directory
    const existing = JSON.stringify({
      client_id: 'existing-id',
      client_key: 'existing-key',
    })
    writeFileSync(join(workspaceDir(), 'secretkey.json'), existing)

    const r = await bindClientDevice()
    if (r.failure) {
      expect.unreachable(`bindClientDevice failed: ${r.failure.type}`)
    }

    const raw = readFileSync(join(workspaceDir(), 'secretkey.json'), 'utf-8')
    const secretKey = JSON.parse(raw)
    expect(secretKey.client_id).toBe('existing-id')
  })

  it('fails with STORE_ERROR when auth token is missing', async () => {
    // No token saved — should fail trying to load auth.json
    const r = await bindClientDevice()
    expect(r.failure?.error).toBeInstanceOf(Error)
    expect(r.failure?.type).toBe('STORE_ERROR')
  })
})
