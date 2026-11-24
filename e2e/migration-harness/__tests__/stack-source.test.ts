import { afterEach, expect, test, vi } from 'vitest'

const npmView = vi.hoisted(() => new Map<string, string>())

vi.mock('node:child_process', () => ({
  execFile: (
    _command: string,
    args: string[],
    callback: (error: Error | null, result?: { stdout: string }) => void,
  ) => {
    const stdout = npmView.get(args.slice(1, 3).join(' '))
    if (stdout === undefined) callback(Error(`unexpected npm ${args}`))
    else callback(null, { stdout })
  },
}))

const { resolveStack } = await import('../run/stack-source.mjs')

afterEach(() => npmView.clear())

// npm 12 answers `npm view <spec> <field> --json` with an array even when the
// spec names one exact version; older npm answers with the bare value.
test.each([
  ['npm 10 bare values', '"1.2.1"', '"0.33.0"'],
  ['npm 12 single-element arrays', '["1.2.1"]', '["0.33.0"]'],
])('resolves a registry Stack from %s', async (_npm, version, ffi) => {
  npmView.set('@cipherstash/stack@^1.2.1 version', version)
  npmView.set(
    '@cipherstash/stack@1.2.1 dependencies.@cipherstash/protect-ffi',
    ffi,
  )
  await expect(
    resolveStack({ source: '^1.2.1', root: '/', output: '/' }),
  ).resolves.toEqual({ version: '1.2.1', install: '1.2.1', ffiRange: '0.33.0' })
})

test('rejects an ambiguous FFI dependency answer', async () => {
  npmView.set('@cipherstash/stack@1.2.1 version', '"1.2.1"')
  npmView.set(
    '@cipherstash/stack@1.2.1 dependencies.@cipherstash/protect-ffi',
    '["0.33.0","0.34.0"]',
  )
  await expect(
    resolveStack({ source: '1.2.1', root: '/', output: '/' }),
  ).rejects.toThrow('Could not resolve Stack FFI dependency')
})
