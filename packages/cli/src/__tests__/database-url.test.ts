import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { messages } from '../messages.js'

// Mock seams. We hoist them so the in-test reconfiguration touches the same
// fn instances the resolver imports.
const supabase = vi.hoisted(() => ({ execSync: vi.fn() }))
vi.mock('node:child_process', () => ({ execSync: supabase.execSync }))

const detect = vi.hoisted(() => ({ detectSupabaseProject: vi.fn() }))
vi.mock('../commands/db/detect.js', () => ({
  detectSupabaseProject: detect.detectSupabaseProject,
}))

const clack = vi.hoisted(() => ({
  text: vi.fn(),
  isCancel: vi.fn(),
  cancel: vi.fn(),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
  note: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  text: clack.text,
  isCancel: clack.isCancel,
  cancel: clack.cancel,
  log: clack.log,
  note: clack.note,
}))

const { resolveDatabaseUrl } = await import('../config/database-url.js')

const VALID_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres'

let originalEnv: string | undefined
let originalCi: string | undefined
let originalIsTty: boolean | undefined
let tmpDir: string

function noProject() {
  detect.detectSupabaseProject.mockReturnValue({
    hasMigrationsDir: false,
    hasConfigToml: false,
    migrationsDir: '/tmp/x',
  })
}

beforeEach(() => {
  originalEnv = process.env.DATABASE_URL
  originalCi = process.env.CI
  originalIsTty = process.stdin.isTTY
  // biome-ignore lint/performance/noDelete: see config-jiti-integration.test.ts; need an actual unset.
  delete process.env.DATABASE_URL
  // biome-ignore lint/performance/noDelete: ditto.
  delete process.env.CI
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'database-url-test-'))
  noProject()
})

afterEach(() => {
  if (originalEnv === undefined) {
    // biome-ignore lint/performance/noDelete: unset, not assignment.
    delete process.env.DATABASE_URL
  } else {
    process.env.DATABASE_URL = originalEnv
  }
  if (originalCi === undefined) {
    // biome-ignore lint/performance/noDelete: unset, not assignment.
    delete process.env.CI
  } else {
    process.env.CI = originalCi
  }
  Object.defineProperty(process.stdin, 'isTTY', {
    value: originalIsTty,
    configurable: true,
  })
  vi.clearAllMocks()
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
})

describe('resolveDatabaseUrl — flag source', () => {
  it('uses the flag value and overwrites env, even when env was already set', async () => {
    process.env.DATABASE_URL = 'postgresql://existing@h/d'
    const result = await resolveDatabaseUrl({ databaseUrlFlag: VALID_URL })
    expect(result).toEqual({ url: VALID_URL, source: 'flag' })
    expect(process.env.DATABASE_URL).toBe(VALID_URL)
    expect(clack.log.info).toHaveBeenCalledWith(messages.db.urlResolvedFromFlag)
  })

  it('exits 1 when the flag is malformed', async () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(
      resolveDatabaseUrl({ databaseUrlFlag: 'not-a-url' }),
    ).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith(messages.db.urlFlagMalformed)
  })
})

describe('resolveDatabaseUrl — env source', () => {
  it('returns the existing env value without mutating', async () => {
    process.env.DATABASE_URL = VALID_URL
    const result = await resolveDatabaseUrl()
    expect(result).toEqual({ url: VALID_URL, source: 'env' })
    // env was already set; we don't reassign.
    expect(process.env.DATABASE_URL).toBe(VALID_URL)
    expect(clack.log.info).not.toHaveBeenCalled()
  })

  it('treats empty-string env as unset and falls through', async () => {
    process.env.DATABASE_URL = ''
    process.env.CI = 'true'
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith(messages.db.urlMissingCi)
  })
})

describe('resolveDatabaseUrl — supabase source', () => {
  it('parses DB_URL from `supabase status --output env`', async () => {
    detect.detectSupabaseProject.mockReturnValue({
      hasMigrationsDir: true,
      hasConfigToml: true,
      migrationsDir: '/tmp/x',
    })
    supabase.execSync.mockReturnValueOnce(`API_URL=http://127.0.0.1:54321
DB_URL=${VALID_URL}
GRAPHQL_URL=http://127.0.0.1:54321/graphql/v1
`)
    const result = await resolveDatabaseUrl()
    expect(result).toEqual({ url: VALID_URL, source: 'supabase-status' })
    expect(process.env.DATABASE_URL).toBe(VALID_URL)
    expect(clack.log.info).toHaveBeenCalledWith(
      messages.db.urlResolvedFromSupabase,
    )
  })

  it('falls through when supabase binary not found', async () => {
    detect.detectSupabaseProject.mockReturnValue({
      hasMigrationsDir: false,
      hasConfigToml: true,
      migrationsDir: '/tmp/x',
    })
    supabase.execSync.mockImplementation(() => {
      const err = new Error('command not found')
      throw err
    })
    process.env.CI = 'true'
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  it('falls through when JSON/env output has no DB_URL', async () => {
    detect.detectSupabaseProject.mockReturnValue({
      hasMigrationsDir: false,
      hasConfigToml: true,
      migrationsDir: '/tmp/x',
    })
    supabase.execSync.mockReturnValue('API_URL=http://127.0.0.1:54321\n')
    process.env.CI = 'true'
    vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
  })

  it('does NOT call supabase when no project is detected and no --supabase flag', async () => {
    process.env.CI = 'true'
    vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
    expect(supabase.execSync).not.toHaveBeenCalled()
  })
})

describe('resolveDatabaseUrl — prompt source', () => {
  beforeEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: true,
      configurable: true,
    })
  })

  it('prompts and uses the entered URL, then suggests a hint file', async () => {
    fs.writeFileSync(path.join(tmpDir, '.env.local'), '')
    clack.text.mockResolvedValueOnce(VALID_URL)
    clack.isCancel.mockReturnValueOnce(false)
    const result = await resolveDatabaseUrl({ cwd: tmpDir })
    expect(result).toEqual({ url: VALID_URL, source: 'prompt' })
    expect(process.env.DATABASE_URL).toBe(VALID_URL)
    expect(clack.note).toHaveBeenCalledWith(messages.db.urlHint('.env.local'))
  })

  it('defaults the hint file to .env when no dotenv files exist', async () => {
    clack.text.mockResolvedValueOnce(VALID_URL)
    clack.isCancel.mockReturnValueOnce(false)
    await resolveDatabaseUrl({ cwd: tmpDir })
    expect(clack.note).toHaveBeenCalledWith(messages.db.urlHint('.env'))
  })

  it('exits 0 when the user cancels the prompt', async () => {
    const cancelSym = Symbol('clack:cancel')
    clack.text.mockResolvedValueOnce(cancelSym)
    clack.isCancel.mockReturnValueOnce(true)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl({ cwd: tmpDir })).rejects.toThrow(
      'process.exit',
    )
    expect(exitSpy).toHaveBeenCalledWith(0)
  })
})

describe('resolveDatabaseUrl — CI guard', () => {
  it('does not prompt and exits 1 when CI=true with no flag and no env', async () => {
    process.env.CI = 'true'
    Object.defineProperty(process.stdin, 'isTTY', {
      value: true,
      configurable: true,
    })
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.text).not.toHaveBeenCalled()
    expect(clack.log.error).toHaveBeenCalledWith(messages.db.urlMissingCi)
  })

  it('does not prompt when stdin is not a TTY (e.g. piped)', async () => {
    Object.defineProperty(process.stdin, 'isTTY', {
      value: false,
      configurable: true,
    })
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(clack.text).not.toHaveBeenCalled()
  })
})
