import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { messages } from '../messages.js'

// Mock seams. Hoisted so the in-test reconfiguration touches the same fn
// instances the resolver imports.
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

const { resolveDatabaseUrl, withResolverContext } = await import(
  '../config/database-url.js'
)

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
  // vitest 4's restoreAllMocks only restores vi.spyOn spies; it no longer
  // clears the call history of vi.fn() mocks. Clear them explicitly so call
  // counts don't bleed between tests.
  vi.clearAllMocks()
  originalEnv = process.env.DATABASE_URL
  originalCi = process.env.CI
  originalIsTty = process.stdin.isTTY
  // biome-ignore lint/performance/noDelete: process.env.X = undefined assigns the string "undefined" in Node, not unset.
  delete process.env.DATABASE_URL
  // biome-ignore lint/performance/noDelete: ditto.
  delete process.env.CI
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'database-url-test-'))
  noProject()
})

afterEach(() => {
  if (originalEnv === undefined) {
    // biome-ignore lint/performance/noDelete: see above.
    delete process.env.DATABASE_URL
  } else {
    process.env.DATABASE_URL = originalEnv
  }
  if (originalCi === undefined) {
    // biome-ignore lint/performance/noDelete: see above.
    delete process.env.CI
  } else {
    process.env.CI = originalCi
  }
  Object.defineProperty(process.stdin, 'isTTY', {
    value: originalIsTty,
    configurable: true,
  })
  // restoreAllMocks (not clearAllMocks) is what fully reverts spies on
  // global objects like `process.exit`. Without restoration the spy stays
  // attached and bleeds into later tests.
  vi.restoreAllMocks()
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
})

describe('resolveDatabaseUrl — flag source', () => {
  it('returns the flag value and does NOT mutate process.env', async () => {
    process.env.DATABASE_URL = 'postgresql://existing@h/d'
    const result = await resolveDatabaseUrl({ databaseUrlFlag: VALID_URL })
    expect(result).toBe(VALID_URL)
    // The whole point of the ALS refactor: env stays untouched.
    expect(process.env.DATABASE_URL).toBe('postgresql://existing@h/d')
    expect(clack.log.info).toHaveBeenCalledWith(messages.db.urlResolvedFromFlag)
  })

  it('reads the flag from withResolverContext when no explicit opts are passed', async () => {
    const result = await withResolverContext(
      { databaseUrlFlag: VALID_URL },
      () => resolveDatabaseUrl(),
    )
    expect(result).toBe(VALID_URL)
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
  it('returns the existing env value without mutating it', async () => {
    process.env.DATABASE_URL = VALID_URL
    const result = await resolveDatabaseUrl()
    expect(result).toBe(VALID_URL)
    expect(process.env.DATABASE_URL).toBe(VALID_URL)
    // The env source is silent — no source label.
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
  it('parses DB_URL from `supabase status --output env` and does NOT mutate process.env', async () => {
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
    expect(result).toBe(VALID_URL)
    // No env mutation under the new design.
    expect(process.env.DATABASE_URL).toBeUndefined()
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
      throw new Error('command not found')
    })
    process.env.CI = 'true'
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit')
    }) as never)
    await expect(resolveDatabaseUrl()).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  it('falls through when supabase env output has no DB_URL', async () => {
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

  it('shows the alternatives tip with the detected dotenv file before prompting', async () => {
    fs.writeFileSync(path.join(tmpDir, '.env.local'), '')
    clack.text.mockResolvedValueOnce(VALID_URL)
    clack.isCancel.mockReturnValueOnce(false)
    await resolveDatabaseUrl({ cwd: tmpDir })
    expect(clack.note).toHaveBeenCalledWith(
      messages.db.urlPromptTip('.env.local'),
    )
    expect(clack.text).toHaveBeenCalled()
  })

  it('defaults the prompt tip to .env when no dotenv files exist', async () => {
    clack.text.mockResolvedValueOnce(VALID_URL)
    clack.isCancel.mockReturnValueOnce(false)
    await resolveDatabaseUrl({ cwd: tmpDir })
    expect(clack.note).toHaveBeenCalledWith(messages.db.urlPromptTip('.env'))
  })

  it('returns the entered URL and suggests an existing dotenv file', async () => {
    fs.writeFileSync(path.join(tmpDir, '.env.local'), '')
    clack.text.mockResolvedValueOnce(VALID_URL)
    clack.isCancel.mockReturnValueOnce(false)
    const result = await resolveDatabaseUrl({ cwd: tmpDir })
    expect(result).toBe(VALID_URL)
    // No env mutation.
    expect(process.env.DATABASE_URL).toBeUndefined()
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
  it.each(['true', 'TRUE', '1', ' true '])(
    'does not prompt and exits 1 when CI=%j (truthy)',
    async (ciValue) => {
      process.env.CI = ciValue
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
    },
  )

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

describe('withResolverContext — concurrent isolation', () => {
  // The whole reason we use AsyncLocalStorage instead of module-level
  // state: two concurrent calls must each see their own options without
  // stepping on each other.
  it('isolates contexts across concurrent withResolverContext scopes', async () => {
    const URL_A = 'postgresql://a:a@h/a'
    const URL_B = 'postgresql://b:b@h/b'

    const [a, b] = await Promise.all([
      withResolverContext({ databaseUrlFlag: URL_A }, async () => {
        // Yield to let the other branch start its scope before we read.
        await new Promise((res) => setTimeout(res, 5))
        return resolveDatabaseUrl()
      }),
      withResolverContext({ databaseUrlFlag: URL_B }, async () => {
        await new Promise((res) => setTimeout(res, 5))
        return resolveDatabaseUrl()
      }),
    ])

    expect(a).toBe(URL_A)
    expect(b).toBe(URL_B)
  })
})
