import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  detectPackageManager,
  devInstallCommand,
  isPackageInstalled,
  prodInstallCommand,
  runnerCommand,
} from '../utils.js'

describe('detectPackageManager', () => {
  let tmp: string
  let originalUserAgent: string | undefined
  let cwdSpy: ReturnType<typeof vi.spyOn> | undefined

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'init-utils-test-'))
    originalUserAgent = process.env.npm_config_user_agent
    delete process.env.npm_config_user_agent
    cwdSpy = vi.spyOn(process, 'cwd').mockReturnValue(tmp)
  })

  afterEach(() => {
    cwdSpy?.mockRestore()
    rmSync(tmp, { recursive: true, force: true })
    if (originalUserAgent === undefined) {
      delete process.env.npm_config_user_agent
    } else {
      process.env.npm_config_user_agent = originalUserAgent
    }
  })

  it('defaults to npm when no lockfile and no user agent', () => {
    expect(detectPackageManager()).toBe('npm')
  })

  it('detects bun from bun.lock', () => {
    writeFileSync(join(tmp, 'bun.lock'), '')
    expect(detectPackageManager()).toBe('bun')
  })

  it('detects bun from bun.lockb', () => {
    writeFileSync(join(tmp, 'bun.lockb'), '')
    expect(detectPackageManager()).toBe('bun')
  })

  it('detects pnpm from pnpm-lock.yaml', () => {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), '')
    expect(detectPackageManager()).toBe('pnpm')
  })

  it('detects yarn from yarn.lock', () => {
    writeFileSync(join(tmp, 'yarn.lock'), '')
    expect(detectPackageManager()).toBe('yarn')
  })

  it('honours bunx via npm_config_user_agent without a lockfile', () => {
    process.env.npm_config_user_agent = 'bun/1.1.40 npm/? node/v22.3.0'
    expect(detectPackageManager()).toBe('bun')
  })

  it('honours pnpm dlx via user agent', () => {
    process.env.npm_config_user_agent = 'pnpm/9.0.0 npm/? node/v20.0.0'
    expect(detectPackageManager()).toBe('pnpm')
  })

  it('honours yarn dlx via user agent', () => {
    process.env.npm_config_user_agent = 'yarn/4.0.0 npm/? node/v20.0.0'
    expect(detectPackageManager()).toBe('yarn')
  })

  it('lets non-npm user agent win over a mismatched lockfile', () => {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), '')
    process.env.npm_config_user_agent = 'bun/1.1.40 npm/? node/v22.3.0'
    expect(detectPackageManager()).toBe('bun')
  })

  it('ignores npm/npx user agent in favour of lockfile', () => {
    writeFileSync(join(tmp, 'bun.lock'), '')
    process.env.npm_config_user_agent = 'npm/10.2.4 node/v20.0.0'
    expect(detectPackageManager()).toBe('bun')
  })
})

describe('prodInstallCommand', () => {
  it('returns bun add for bun', () => {
    expect(prodInstallCommand('bun', '@cipherstash/stack')).toBe(
      'bun add @cipherstash/stack',
    )
  })

  it('returns pnpm add for pnpm', () => {
    expect(prodInstallCommand('pnpm', '@cipherstash/stack')).toBe(
      'pnpm add @cipherstash/stack',
    )
  })

  it('returns yarn add for yarn', () => {
    expect(prodInstallCommand('yarn', '@cipherstash/stack')).toBe(
      'yarn add @cipherstash/stack',
    )
  })

  it('returns npm install for npm', () => {
    expect(prodInstallCommand('npm', '@cipherstash/stack')).toBe(
      'npm install @cipherstash/stack',
    )
  })
})

describe('devInstallCommand', () => {
  it('returns bun add -D for bun', () => {
    expect(devInstallCommand('bun', 'stash')).toBe('bun add -D stash')
  })

  it('returns pnpm add -D for pnpm', () => {
    expect(devInstallCommand('pnpm', 'stash')).toBe('pnpm add -D stash')
  })

  it('returns yarn add -D for yarn', () => {
    expect(devInstallCommand('yarn', 'stash')).toBe('yarn add -D stash')
  })

  it('returns npm install -D for npm', () => {
    expect(devInstallCommand('npm', 'stash')).toBe('npm install -D stash')
  })
})

describe('runnerCommand', () => {
  it('returns npx for npm', () => {
    expect(runnerCommand('npm', 'stash')).toBe('npx stash')
  })

  it('returns bunx for bun', () => {
    expect(runnerCommand('bun', 'stash')).toBe('bunx stash')
  })

  it('returns pnpm dlx for pnpm', () => {
    expect(runnerCommand('pnpm', 'stash')).toBe('pnpm dlx stash')
  })

  it('returns yarn dlx for yarn', () => {
    expect(runnerCommand('yarn', 'stash')).toBe('yarn dlx stash')
  })

  it('passes the package reference through verbatim (multi-word args allowed)', () => {
    expect(runnerCommand('bun', 'stash db install')).toBe(
      'bunx stash db install',
    )
  })
})

describe('isPackageInstalled', () => {
  let tmp: string
  let cwdSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'isinstalled-test-'))
    cwdSpy = vi.spyOn(process, 'cwd').mockReturnValue(tmp)
  })

  afterEach(() => {
    cwdSpy.mockRestore()
    rmSync(tmp, { recursive: true, force: true })
  })

  it('returns false when node_modules/<name> does not exist', () => {
    expect(isPackageInstalled('stash')).toBe(false)
  })

  it('returns true when node_modules/<name>/package.json exists', () => {
    const pkgDir = join(tmp, 'node_modules', 'stash')
    mkdirSync(pkgDir, { recursive: true })
    writeFileSync(join(pkgDir, 'package.json'), '{"name":"stash"}')
    expect(isPackageInstalled('stash')).toBe(true)
  })

  it('returns false when the directory exists but no package.json', () => {
    // The bug we fixed: a leftover dir from an aborted install or stale
    // workspace symlink would previously be treated as a real install.
    const pkgDir = join(tmp, 'node_modules', 'stash')
    mkdirSync(pkgDir, { recursive: true })
    expect(isPackageInstalled('stash')).toBe(false)
  })

  it('handles scoped package names', () => {
    const pkgDir = join(tmp, 'node_modules', '@cipherstash', 'stack')
    mkdirSync(pkgDir, { recursive: true })
    writeFileSync(join(pkgDir, 'package.json'), '{"name":"@cipherstash/stack"}')
    expect(isPackageInstalled('@cipherstash/stack')).toBe(true)
  })
})
