import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('jiti', () => ({
  createJiti: vi.fn(),
}))

describe('loadStashConfig', () => {
  let tmpDir: string
  let originalCwd: () => string

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-forge-config-test-'))
    originalCwd = process.cwd
  })

  afterEach(() => {
    process.cwd = originalCwd
    vi.restoreAllMocks()

    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('throws when stash.config.ts is missing', async () => {
    process.cwd = () => tmpDir
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const { loadStashConfig } = await import('@/config/index.ts')

    await expect(loadStashConfig()).rejects.toThrow('process.exit')
  })

  it('points the user at `init` / `eql install` when config is missing (#578)', async () => {
    process.cwd = () => tmpDir
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const { loadStashConfig } = await import('@/config/index.ts')
    await expect(loadStashConfig()).rejects.toThrow('process.exit')

    const output = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n')
    expect(output).toContain('stash init')
    expect(output).toContain('stash eql install')
  })

  it.each([
    ['stash', `Cannot find module 'stash'`],
    ['@cipherstash/stack', `Cannot find package '@cipherstash/stack'`],
  ])('translates a missing `%s` module into actionable guidance (#579)', async (pkg, message) => {
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `import 'stash'\nexport default {}`,
    )
    process.cwd = () => tmpDir
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const moduleErr = Object.assign(new Error(message), {
      code: 'MODULE_NOT_FOUND',
    })
    const { createJiti } = await import('jiti')
    vi.mocked(createJiti).mockReturnValue({
      import: vi.fn().mockRejectedValue(moduleErr),
    } as never)

    const { loadStashConfig } = await import('@/config/index.ts')
    await expect(loadStashConfig()).rejects.toThrow('process.exit')

    const output = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n')
    expect(output).toContain(`\`${pkg}\` is not installed`)
    expect(output).toContain('stash init')
    // The raw jiti stack trace must NOT be forwarded to the user.
    expect(output).not.toContain('Failed to load')
  })

  it('still surfaces the raw error for unrelated config load failures', async () => {
    fs.writeFileSync(path.join(tmpDir, 'stash.config.ts'), 'export default {}')
    process.cwd = () => tmpDir
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const { createJiti } = await import('jiti')
    vi.mocked(createJiti).mockReturnValue({
      import: vi.fn().mockRejectedValue(new SyntaxError('Unexpected token')),
    } as never)

    const { loadStashConfig } = await import('@/config/index.ts')
    await expect(loadStashConfig()).rejects.toThrow('process.exit')

    const output = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n')
    expect(output).toContain('Failed to load')
  })

  it('validates required fields', async () => {
    // Write a config file that exists but exports an empty object
    fs.writeFileSync(path.join(tmpDir, 'stash.config.ts'), 'export default {}')

    process.cwd = () => tmpDir
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const { createJiti } = await import('jiti')
    const mockJiti = {
      import: vi.fn().mockResolvedValue({}),
    }
    vi.mocked(createJiti).mockReturnValue(mockJiti as never)

    const { loadStashConfig } = await import('@/config/index.ts')

    await expect(loadStashConfig()).rejects.toThrow('process.exit')
  })

  it('succeeds with valid config', async () => {
    const validConfig = { databaseUrl: 'postgresql://localhost:5432/test' }

    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `export default { databaseUrl: 'postgresql://localhost:5432/test' }`,
    )

    process.cwd = () => tmpDir

    const { createJiti } = await import('jiti')
    const mockJiti = {
      import: vi.fn().mockResolvedValue(validConfig),
    }
    vi.mocked(createJiti).mockReturnValue(mockJiti as never)

    const { loadStashConfig } = await import('@/config/index.ts')

    const config = await loadStashConfig()
    expect(config).toEqual({
      ...validConfig,
      client: './src/encryption/index.ts',
    })
  })
})

describe('loadEncryptConfig', () => {
  let tmpDir: string
  let originalCwd: () => string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(
      path.join(os.tmpdir(), 'stash-encrypt-config-test-'),
    )
    originalCwd = process.cwd
  })

  afterEach(() => {
    process.cwd = originalCwd
    vi.restoreAllMocks()
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('translates a missing @cipherstash/stack in the client file into guidance (#3)', async () => {
    // The client (not the config) is what imports @cipherstash/stack, incl.
    // subpaths. This path used to dump a raw jiti stack trace.
    fs.writeFileSync(path.join(tmpDir, 'client.ts'), '// encryption client')
    process.cwd = () => tmpDir
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const moduleErr = Object.assign(
      new Error("Cannot find module '@cipherstash/stack/schema'"),
      { code: 'MODULE_NOT_FOUND' },
    )
    const { createJiti } = await import('jiti')
    vi.mocked(createJiti).mockReturnValue({
      import: vi.fn().mockRejectedValue(moduleErr),
    } as never)

    const { loadEncryptConfig } = await import('@/config/index.ts')
    await expect(loadEncryptConfig('client.ts')).rejects.toThrow('process.exit')

    const output = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n')
    expect(output).toContain('`@cipherstash/stack` is not installed')
    expect(output).toContain('stash init')
    // Not the raw stack-trace path.
    expect(output).not.toContain('Failed to load encrypt client')
  })
})
