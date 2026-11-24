import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, test } from 'vitest'
import { declaredStack } from '../run/migration-checks.mjs'

const directories: string[] = []
afterEach(async () => {
  for (const path of directories.splice(0))
    await rm(path, { recursive: true, force: true })
})
async function workspace(files: Record<string, string>) {
  const directory = await mkdtemp(join(tmpdir(), 'mh-declared-stack-'))
  directories.push(directory)
  for (const [name, text] of Object.entries(files))
    await writeFile(join(directory, name), text)
  return directory
}
const lock = (version: unknown) =>
  JSON.stringify({
    packages: { 'node_modules/@cipherstash/stack': { version } },
  })

test('records the Stack the migrated workspace declares and locks', async () => {
  const directory = await workspace({
    'package.json': JSON.stringify({
      dependencies: { '@cipherstash/stack': '^1.2.0' },
    }),
    'package-lock.json': lock('1.2.1'),
  })
  expect(await declaredStack(directory)).toEqual({
    specifier: '^1.2.0',
    locked: '1.2.1',
  })
})

test('reads a Stack declared as a development dependency', async () => {
  const directory = await workspace({
    'package.json': JSON.stringify({
      devDependencies: { '@cipherstash/stack': 'file:./resolved-stack.tgz' },
    }),
  })
  expect(await declaredStack(directory)).toEqual({
    specifier: 'file:./resolved-stack.tgz',
    locked: null,
  })
})

test.each([
  ['no manifest or lock', {}],
  ['malformed JSON', { 'package.json': '{', 'package-lock.json': '[' }],
  [
    'no Stack dependency',
    { 'package.json': '{"dependencies":{}}', 'package-lock.json': '{}' },
  ],
  [
    'values that are not strings',
    {
      'package.json': JSON.stringify({
        dependencies: { '@cipherstash/stack': { nested: true } },
      }),
      'package-lock.json': lock(7),
    },
  ],
  [
    'an oversized specifier',
    {
      'package.json': JSON.stringify({
        dependencies: { '@cipherstash/stack': 'x'.repeat(257) },
      }),
    },
  ],
])('records null for %s', async (_name, files) => {
  expect(await declaredStack(await workspace(files))).toEqual({
    specifier: null,
    locked: null,
  })
})

test('does not follow a symlinked manifest out of the workspace', async () => {
  const outside = await workspace({
    'package.json': JSON.stringify({
      dependencies: { '@cipherstash/stack': 'outside' },
    }),
  })
  const directory = await workspace({})
  await symlink(join(outside, 'package.json'), join(directory, 'package.json'))
  expect(await declaredStack(directory)).toEqual({
    specifier: null,
    locked: null,
  })
})
