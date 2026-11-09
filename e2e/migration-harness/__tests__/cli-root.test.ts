import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { expect, test, vi } from 'vitest'

const observed = vi.hoisted(() => ({ root: '' }))
vi.mock('../run/real-driver.mjs', () => ({
  createRealDriver: (options: { root: string }) => {
    observed.root = options.root
    return {
      provision: async () => {},
      installUnmigrated: async () => {},
      initializeLegacyData: async () => {},
      snapshot: async () => {},
      migrate: async () => ({ exitCode: 0 }),
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () => [{ id: 'behaviour.cli', passed: true }],
      close: async () => {},
    }
  },
}))
vi.mock('../isolation.mjs', () => ({
  createIsolation: () => ({ drain: () => [], stop: async () => {} }),
}))

test('CLI resolves the checkout root and writes a report with its real Fixture App revision', async () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url)).replace(
    /\/$/,
    '',
  )
  const output = await mkdtemp(join(tmpdir(), 'mh-cli-root-'))
  const argv = process.argv
  const exitCode = process.exitCode
  const diagnostics = vi.spyOn(console, 'error').mockImplementation(() => {})
  try {
    process.argv = ['node', 'cli.mjs', '--migrator', 'fake', '--output', output]
    const expectedRevision = (
      await promisify(execFile)('git', ['rev-parse', 'HEAD'], { cwd: root })
    ).stdout.trim()
    let failure: unknown
    try {
      await import('../run/cli.mjs')
    } catch (error) {
      failure = error
    }
    expect(
      failure,
      'CLI must reach the Run and report stages from the actual checkout',
    ).toBeUndefined()
    expect(observed.root).toBe(root)
    expect(
      (
        await stat(
          join(observed.root, 'e2e/migration-harness/fixture/src/app.mjs'),
        )
      ).isFile(),
    ).toBe(true)
    const report = JSON.parse(
      await readFile(join(output, 'run-report.json'), 'utf8'),
    )
    expect(report.manifest.fixtureRevision).toBe(expectedRevision)
    expect(report.outcome).toBe('pass')
  } finally {
    process.argv = argv
    process.exitCode = exitCode
    diagnostics.mockRestore()
    await rm(output, { recursive: true, force: true })
  }
})
