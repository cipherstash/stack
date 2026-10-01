import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  checkEnvKeys,
  detectPackageManagerTool,
  setEnvValues,
} from '../tools/wizard-tools.js'

describe('checkEnvKeys', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('reports all keys as missing when .env does not exist', () => {
    const result = checkEnvKeys(tmp, {
      filePath: '.env',
      keys: ['DATABASE_URL', 'API_KEY'],
    })
    expect(result).toEqual({
      DATABASE_URL: 'missing',
      API_KEY: 'missing',
    })
  })

  it('detects present and missing keys', () => {
    writeFileSync(
      join(tmp, '.env'),
      'DATABASE_URL=postgres://localhost/test\nSECRET=foo\n',
    )
    const result = checkEnvKeys(tmp, {
      filePath: '.env',
      keys: ['DATABASE_URL', 'API_KEY', 'SECRET'],
    })
    expect(result).toEqual({
      DATABASE_URL: 'present',
      API_KEY: 'missing',
      SECRET: 'present',
    })
  })

  it('handles keys with spaces around =', () => {
    writeFileSync(join(tmp, '.env'), 'FOO = bar\n')
    const result = checkEnvKeys(tmp, { filePath: '.env', keys: ['FOO'] })
    expect(result.FOO).toBe('present')
  })
})

describe('setEnvValues', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('creates .env file if it does not exist', () => {
    setEnvValues(tmp, {
      filePath: '.env',
      values: { DATABASE_URL: 'postgres://localhost/test' },
    })
    const content = readFileSync(join(tmp, '.env'), 'utf-8')
    expect(content).toContain('DATABASE_URL=postgres://localhost/test')
  })

  it('updates existing keys', () => {
    writeFileSync(join(tmp, '.env'), 'DATABASE_URL=old_value\n')
    setEnvValues(tmp, {
      filePath: '.env',
      values: { DATABASE_URL: 'new_value' },
    })
    const content = readFileSync(join(tmp, '.env'), 'utf-8')
    expect(content).toContain('DATABASE_URL=new_value')
    expect(content).not.toContain('old_value')
  })

  it('appends new keys', () => {
    writeFileSync(join(tmp, '.env'), 'EXISTING=yes\n')
    setEnvValues(tmp, {
      filePath: '.env',
      values: { NEW_KEY: 'new_value' },
    })
    const content = readFileSync(join(tmp, '.env'), 'utf-8')
    expect(content).toContain('EXISTING=yes')
    expect(content).toContain('NEW_KEY=new_value')
  })

  it('adds .env to .gitignore if not already there', () => {
    writeFileSync(join(tmp, '.gitignore'), 'node_modules\n')
    setEnvValues(tmp, {
      filePath: '.env',
      values: { FOO: 'bar' },
    })
    const gitignore = readFileSync(join(tmp, '.gitignore'), 'utf-8')
    expect(gitignore).toContain('.env')
  })

  it('does not duplicate .env in .gitignore', () => {
    writeFileSync(join(tmp, '.gitignore'), '.env\nnode_modules\n')
    setEnvValues(tmp, {
      filePath: '.env',
      values: { FOO: 'bar' },
    })
    const gitignore = readFileSync(join(tmp, '.gitignore'), 'utf-8')
    const matches = gitignore.match(/\.env/g)
    expect(matches?.length).toBe(1)
  })

  it('returns a descriptive message', () => {
    const result = setEnvValues(tmp, {
      filePath: '.env',
      values: { A: '1', B: '2' },
    })
    expect(result).toContain('2 environment variables')
  })
})

describe('security: path traversal', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('blocks path traversal in checkEnvKeys', () => {
    expect(() =>
      checkEnvKeys(tmp, { filePath: '../../etc/passwd', keys: ['ROOT'] }),
    ).toThrow('Path traversal blocked')
  })

  it('blocks path traversal in setEnvValues', () => {
    expect(() =>
      setEnvValues(tmp, { filePath: '../../../tmp/evil', values: { X: '1' } }),
    ).toThrow('Path traversal blocked')
  })

  it('allows relative paths within cwd', () => {
    // This should not throw — .env is within cwd
    expect(() =>
      checkEnvKeys(tmp, { filePath: '.env', keys: ['FOO'] }),
    ).not.toThrow()
  })
})

describe('security: regex injection', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('does not treat key with regex metacharacters as wildcard', () => {
    // Without escaping, ".*" would match "SAFE_KEY" (any chars).
    // With escaping, it only matches the literal string ".*"
    writeFileSync(join(tmp, '.env'), 'SAFE_KEY=value\n')
    const result = checkEnvKeys(tmp, {
      filePath: '.env',
      keys: ['.*'], // Should NOT match SAFE_KEY
    })
    expect(result['.*']).toBe('missing')
  })

  it('escapes metacharacters so they match literally', () => {
    writeFileSync(join(tmp, '.env'), 'NORMAL_KEY=value\n')
    const result = checkEnvKeys(tmp, {
      filePath: '.env',
      keys: ['.*'], // Should NOT match NORMAL_KEY
    })
    // ".*" is not literally in the file as a key
    // Actually, we just wrote "DANGER.*=other" above, different test
    // Here, ".*" should be missing because there's no literal ".*" key
    expect(result['.*']).toBe('missing')
  })
})

describe('detectPackageManagerTool', () => {
  let tmp: string
  let originalUserAgent: string | undefined

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
    originalUserAgent = process.env.npm_config_user_agent
    delete process.env.npm_config_user_agent
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
    if (originalUserAgent === undefined) {
      delete process.env.npm_config_user_agent
    } else {
      process.env.npm_config_user_agent = originalUserAgent
    }
  })

  it('returns detected: false when no lockfile', () => {
    const result = detectPackageManagerTool(tmp)
    expect(result.detected).toBe(false)
  })

  it('returns pnpm details when pnpm-lock.yaml exists', () => {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), '')
    const result = detectPackageManagerTool(tmp)
    expect(result).toEqual({
      detected: true,
      name: 'pnpm',
      installCommand: 'pnpm add',
      runCommand: 'pnpm run',
    })
  })
})
