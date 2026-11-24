import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test, vi } from 'vitest'
import { requiredOracleChecks } from '../run/migration-checks.mjs'

vi.mock('../run/real-driver.mjs', () => ({
  createRealDriver: () => ({
    provision: async () => {},
    installUnmigrated: async () => {},
    initializeLegacyData: async () => {},
    snapshot: async () => {},
    migrate: async () => ({ exitCode: 0 }),
    friction: async () => [],
    installAppHost: async () => {},
    behaviour: async () => [
      { id: 'behaviour.cli', passed: true },
      ...requiredOracleChecks.map((id) => ({ id, passed: true })),
    ],
    close: async () => {},
  }),
}))
vi.mock('../isolation.mjs', () => ({
  createIsolation: () => ({ drain: () => [], stop: async () => {} }),
}))

test('a Fake Migrator Run records its variant rather than a command adapter', async () => {
  const output = await mkdtemp(join(tmpdir(), 'mh-cli-fake-'))
  const argv = process.argv
  const exitCode = process.exitCode
  const diagnostics = vi.spyOn(console, 'error').mockImplementation(() => {})
  try {
    process.argv = ['node', 'cli.mjs', '--fake', 'downcase', '--output', output]
    await import('../run/cli.mjs')
    const report = JSON.parse(
      await readFile(join(output, 'run-report.json'), 'utf8'),
    )
    expect(report.manifest.agents).toMatchObject({
      migrator: 'fake:downcase',
      model: 'fake-migrator',
    })
  } finally {
    process.argv = argv
    process.exitCode = exitCode
    diagnostics.mockRestore()
    await rm(output, { recursive: true, force: true })
  }
})
