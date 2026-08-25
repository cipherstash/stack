import { describe, expect, it } from 'vitest'
import { runPiped } from '../helpers/spawn-piped.js'

const output = (result: { stdout: string; stderr: string }) =>
  `${result.stdout}\n${result.stderr}`

describe('retired EQL v2 CLI surface', () => {
  it('rejects v2 installation before database access and links recovery SQL', async () => {
    const result = await runPiped(['eql', 'install', '--eql-version', '2'])

    expect(result.exitCode).toBe(1)
    expect(output(result)).toContain(
      'https://github.com/cipherstash/encrypt-query-language/releases/tag/eql-2.3.1',
    )
  })

  it('rejects the obsolete operator-family install flag before database access', async () => {
    const result = await runPiped([
      'eql',
      'install',
      '--exclude-operator-family',
    ])

    expect(result.exitCode).toBe(1)
    expect(output(result)).toMatch(/self-adapts/i)
  })

  it.each([
    ['--proxy', '--proxy'],
    ['--no-proxy', '--no-proxy'],
    ['--proxy=true', '--proxy'],
    ['--no-proxy=true', '--no-proxy'],
  ] as const)(
    'rejects retired init flag `%s` before init work',
    async (arg, flag) => {
      const result = await runPiped(['init', arg], { timeoutMs: 2_000 })

      expect(result.timedOut).toBe(false)
      expect(result.exitCode).toBe(1)
      expect(output(result)).toContain(flag)
      expect(output(result)).toMatch(/removed|retired/i)
      expect(output(result)).toMatch(/EQL v3/i)
    },
  )

  it.each([
    '--eql-version=2',
    '--latest=true',
    '--drizzle=true',
    '--name=install-eql',
    '--out=drizzle',
    '--migration=true',
    '--migrations-dir=drizzle',
    '--direct=true',
    '--exclude-operator-family=true',
  ])('rejects retired eql install equals form `%s`', async (arg) => {
    const result = await runPiped(['eql', 'install', arg])

    expect(result.exitCode).toBe(1)
    expect(output(result)).toMatch(/removed/i)
  })

  it.each([
    [['db', 'push'], 'db push'],
    [['db', 'activate'], 'db activate'],
    [['encrypt', 'cutover'], 'encrypt cutover'],
  ] as const)('rejects removed `%s` routing', async (args, command) => {
    const result = await runPiped([...args])

    expect(result.exitCode).toBe(1)
    expect(output(result)).toContain(command)
    expect(output(result)).toMatch(/removed/i)
  })
})
