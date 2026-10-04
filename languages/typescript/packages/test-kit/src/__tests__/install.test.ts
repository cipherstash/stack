import { beforeEach, describe, expect, it, vi } from 'vitest'

const { execFileMock } = vi.hoisted(() => ({ execFileMock: vi.fn() }))

vi.mock('node:child_process', () => ({ execFile: execFileMock }))
vi.mock('node:fs', () => ({ existsSync: vi.fn(() => true) }))

const { installEqlV3 } = await import('../install.js')

beforeEach(() => {
  execFileMock.mockReset().mockImplementation((...args: unknown[]) => {
    const callback = args.at(-1) as (
      error: Error | null,
      stdout: string,
      stderr: string,
    ) => void
    callback(null, '', '')
  })
})

describe('installEqlV3 CLI argv', () => {
  it.each([
    ['postgres', []],
    ['supabase', ['--supabase']],
  ] as const)('uses the current %s install surface', async (variant, flags) => {
    await installEqlV3('postgres://integration', variant)

    expect(execFileMock).toHaveBeenCalledTimes(1)
    expect(execFileMock.mock.calls[0]?.[1]).toEqual([
      expect.stringMatching(/packages\/cli\/dist\/bin\/stash\.js$/),
      'eql',
      'install',
      ...flags,
      '--database-url',
      'postgres://integration',
    ])
  })

  it('reports the supported Supabase invocation when the installer fails', async () => {
    execFileMock.mockImplementationOnce((...args: unknown[]) => {
      const callback = args.at(-1) as (error: Error) => void
      callback(new Error('installer exploded'))
    })

    const result = installEqlV3('postgres://integration', 'supabase')
    await expect(result).rejects.toThrow(
      /^stash eql install --supabase failed\./,
    )
    await expect(result).rejects.not.toThrow(/--eql-version|--direct/)
  })
})
