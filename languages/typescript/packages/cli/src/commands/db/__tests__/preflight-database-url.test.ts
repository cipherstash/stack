import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { PreflightResult } from '@/installer/index.js'

// Which database `stash eql preflight` probes, with and without
// `--database-url`, when a stash.config.ts sets a literal `databaseUrl` (#1966).
// The config file is real and loaded through the real loader; only the
// database is faked, by recording the URL the installer is built with.

const probedUrls: string[] = []

const CAPABLE: PreflightResult = {
  currentUser: 'postgres',
  isSuperuser: true,
  memberOfPostgres: true,
  hasDatabaseCreate: true,
  hasPublicCreate: true,
  pgcryptoInstalled: true,
  pgcryptoSchema: 'extensions',
  eqlV3SchemaPresent: false,
  eqlV3InternalSchemaPresent: false,
  canDropEqlV3Schema: null,
  canDropEqlV3InternalSchema: null,
  canCreateOperatorClass: true,
  missing: [],
  ok: true,
}

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  spinner: () => ({ start: vi.fn(), stop: vi.fn() }),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), step: vi.fn() },
}))
vi.mock('@/installer/index.js', () => ({
  EQLInstaller: class {
    constructor({ databaseUrl }: { databaseUrl: string }) {
      probedUrls.push(databaseUrl)
    }
    preflight = () => Promise.resolve(CAPABLE)
  },
}))

const CONFIG_URL = 'postgres://config-host/config_db'
const FLAG_URL = 'postgres://flag-host/flag_db'
const ENV_URL = 'postgres://env-host/env_db'

let projectDir: string

function writeLiteralConfig(): void {
  fs.writeFileSync(
    path.join(projectDir, 'stash.config.ts'),
    `export default { databaseUrl: '${CONFIG_URL}' }\n`,
  )
}

beforeEach(() => {
  probedUrls.length = 0
  projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-preflight-'))
  vi.spyOn(process, 'cwd').mockReturnValue(projectDir)
  vi.stubEnv('DATABASE_URL', ENV_URL)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  fs.rmSync(projectDir, { recursive: true, force: true })
})

describe('stash eql preflight database URL', () => {
  it('probes the --database-url database, not the config literal', async () => {
    writeLiteralConfig()
    const { preflightCommand } = await import('../preflight.js')
    await preflightCommand({ databaseUrl: FLAG_URL })
    expect(probedUrls).toEqual([FLAG_URL])
  })

  it('probes the --database-url database in --json mode, with no warning', async () => {
    writeLiteralConfig()
    const stdout = vi.spyOn(console, 'log').mockImplementation(() => {})
    const stderr = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true)
    const { preflightCommand } = await import('../preflight.js')
    await preflightCommand({ databaseUrl: FLAG_URL, json: true })
    expect(probedUrls).toEqual([FLAG_URL])
    expect(stderr).not.toHaveBeenCalled()
    expect(String(stdout.mock.calls[0]?.[0])).toContain('"status":"ok"')
  })

  it('probes the config literal when no flag is given', async () => {
    writeLiteralConfig()
    const { preflightCommand } = await import('../preflight.js')
    await preflightCommand({})
    expect(probedUrls).toEqual([CONFIG_URL])
  })

  it('falls back to DATABASE_URL when there is no flag and no config', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {})
    const { preflightCommand } = await import('../preflight.js')
    await preflightCommand({ json: true })
    expect(probedUrls).toEqual([ENV_URL])
  })
})
