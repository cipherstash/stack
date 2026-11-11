import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test, vi } from 'vitest'

const observed = vi.hoisted(() => ({ created: 0 }))
vi.mock('../run/real-driver.mjs', () => ({
  createRealDriver: () => {
    observed.created++
    throw Error('Driver reached before argument validation')
  },
}))
vi.mock('../isolation.mjs', () => ({
  createIsolation: () => ({ drain: () => [], stop: async () => {} }),
}))

test.each(['migrator', 'output', 'stack'])(
  'F11 rejects missing --%s operands before constructing a driver',
  async (option) => {
    const output = await mkdtemp(join(tmpdir(), 'mh-review-cli-'))
    const argv = process.argv
    const exitCode = process.exitCode
    const diagnostics = vi.spyOn(console, 'error').mockImplementation(() => {})
    observed.created = 0
    vi.resetModules()
    try {
      process.argv = [
        'node',
        'cli.mjs',
        ...(option === 'migrator' ? ['--migrator'] : ['--migrator', 'true']),
        ...(option === 'output' ? [] : ['--output', output]),
        ...(option === 'migrator' ? [] : [`--${option}`]),
      ]
      let failure: unknown
      try {
        await import('../run/cli.mjs')
      } catch (error) {
        failure = error
      }
      expect(failure).toBeInstanceOf(Error)
      expect(failure instanceof Error ? failure.message : '').toMatch(
        /Usage|argument.*missing|argument.*ambiguous/i,
      )
      expect(observed.created).toBe(0)
    } finally {
      process.argv = argv
      process.exitCode = exitCode
      diagnostics.mockRestore()
      await rm(output, { recursive: true, force: true })
    }
  },
)
