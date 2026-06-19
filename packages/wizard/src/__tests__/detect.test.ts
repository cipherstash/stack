import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  detectIntegration,
  detectPackageManager,
  detectTypeScript,
} from '../lib/detect.js'

describe('detectIntegration', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('returns undefined when no package.json exists', () => {
    expect(detectIntegration(tmp)).toBeUndefined()
  })

  it('detects drizzle-orm', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({ dependencies: { 'drizzle-orm': '^0.30.0' } }),
    )
    expect(detectIntegration(tmp)).toBe('drizzle')
  })

  it('detects supabase', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2.0.0' } }),
    )
    expect(detectIntegration(tmp)).toBe('supabase')
  })

  it('detects prisma from dependencies', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({ dependencies: { prisma: '^5.0.0' } }),
    )
    expect(detectIntegration(tmp)).toBe('prisma')
  })

  it('detects prisma from @prisma/client in devDependencies', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({ devDependencies: { '@prisma/client': '^5.0.0' } }),
    )
    expect(detectIntegration(tmp)).toBe('prisma')
  })

  it('prefers drizzle over supabase when both present', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({
        dependencies: {
          'drizzle-orm': '^0.30.0',
          '@supabase/supabase-js': '^2.0.0',
        },
      }),
    )
    expect(detectIntegration(tmp)).toBe('drizzle')
  })

  it('returns undefined for project with unrelated deps', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({ dependencies: { express: '^4.0.0' } }),
    )
    expect(detectIntegration(tmp)).toBeUndefined()
  })
})

describe('detectTypeScript', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('returns false when no package.json or tsconfig', () => {
    expect(detectTypeScript(tmp)).toBe(false)
  })

  it('detects typescript from dependencies', () => {
    writeFileSync(
      join(tmp, 'package.json'),
      JSON.stringify({ devDependencies: { typescript: '^5.0.0' } }),
    )
    expect(detectTypeScript(tmp)).toBe(true)
  })

  it('detects typescript from tsconfig.json', () => {
    writeFileSync(join(tmp, 'tsconfig.json'), '{}')
    expect(detectTypeScript(tmp)).toBe(true)
  })
})

describe('detectPackageManager', () => {
  let tmp: string
  let originalUserAgent: string | undefined

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'wizard-test-'))
    originalUserAgent = process.env.npm_config_user_agent
    // Tests run under a package manager, so the env leaks in and would
    // short-circuit the lockfile branches we want to cover.
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

  it('returns undefined when no lockfile or user agent', () => {
    expect(detectPackageManager(tmp)).toBeUndefined()
  })

  it('detects bun from bun.lock', () => {
    writeFileSync(join(tmp, 'bun.lock'), '')
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('bun')
    expect(pm?.installCommand).toBe('bun add')
    expect(pm?.execCommand).toBe('bunx')
  })

  it('detects bun from bun.lockb', () => {
    writeFileSync(join(tmp, 'bun.lockb'), '')
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('bun')
  })

  it('detects pnpm', () => {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), '')
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('pnpm')
    expect(pm?.installCommand).toBe('pnpm add')
    expect(pm?.execCommand).toBe('pnpm dlx')
  })

  it('detects yarn', () => {
    writeFileSync(join(tmp, 'yarn.lock'), '')
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('yarn')
    expect(pm?.installCommand).toBe('yarn add')
    expect(pm?.execCommand).toBe('yarn dlx')
  })

  it('detects npm', () => {
    writeFileSync(join(tmp, 'package-lock.json'), '')
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('npm')
    expect(pm?.installCommand).toBe('npm install')
    expect(pm?.execCommand).toBe('npx')
  })

  it('honours bunx via npm_config_user_agent with no lockfile', () => {
    process.env.npm_config_user_agent = 'bun/1.1.40 npm/? node/v22.3.0'
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('bun')
    expect(pm?.installCommand).toBe('bun add')
    expect(pm?.execCommand).toBe('bunx')
  })

  it('honours pnpm dlx via user agent', () => {
    process.env.npm_config_user_agent = 'pnpm/9.0.0 npm/? node/v20.0.0'
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('pnpm')
  })

  it('honours yarn dlx via user agent', () => {
    process.env.npm_config_user_agent = 'yarn/4.0.0 npm/? node/v20.0.0'
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('yarn')
  })

  it('user agent wins over a mismatched lockfile', () => {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), '')
    process.env.npm_config_user_agent = 'bun/1.1.40 npm/? node/v22.3.0'
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('bun')
  })

  it('ignores npm/npx user agent and falls through to lockfile', () => {
    writeFileSync(join(tmp, 'bun.lock'), '')
    process.env.npm_config_user_agent = 'npm/10.2.4 node/v20.0.0'
    const pm = detectPackageManager(tmp)
    expect(pm?.name).toBe('bun')
  })
})
