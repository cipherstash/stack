import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { runPiped } from '../helpers/spawn-piped.js'

/**
 * `stash manifest` is pure metadata (no network, no native binary), so these run
 * fast and deterministically. They guard the contract the docs generator and
 * agents depend on: a versioned, grouped, machine-readable command surface.
 */

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf-8'),
) as { version: string }

describe('stash manifest --json', () => {
  it('emits a versioned, grouped manifest and exits 0', async () => {
    const r = await runPiped(['manifest', '--json'])
    expect(r.exitCode).toBe(0)
    const m = JSON.parse(r.stdout) as {
      name: string
      version: string
      groups: Array<{
        title: string
        commands: Array<{ name: string; summary: string }>
      }>
    }
    expect(m.name).toBe('stash')
    // Stamped with the CLI's own version, so generated docs name it correctly.
    expect(m.version).toBe(pkg.version)
    expect(Array.isArray(m.groups)).toBe(true)
    expect(m.groups.length).toBeGreaterThan(0)

    const names = m.groups.flatMap((g) => g.commands.map((c) => c.name))
    expect(names).toContain('auth login')
    expect(names).toContain('eql install')
    expect(names).toContain('manifest')
  })
})

describe('stash manifest (no --json)', () => {
  it('prints a grouped human-readable list and exits 0', async () => {
    const r = await runPiped(['manifest'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain(`stash ${pkg.version}`)
    expect(r.stdout).toContain('auth login')
    expect(r.stdout).toContain('--json')
  })
})

describe('stash --help', () => {
  it('lists the manifest command', async () => {
    const r = await runPiped(['--help'])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('manifest')
  })
})
