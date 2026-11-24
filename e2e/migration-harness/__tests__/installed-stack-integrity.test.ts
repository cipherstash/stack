import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { gzipSync } from 'node:zlib'
import { afterEach, expect, test } from 'vitest'
import { verifyInstalledTarball } from '../run/stack-source.mjs'

const execute = promisify(execFile)
const directories: string[] = []
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true })
})

/** Install offline packages through npm so a dependency hook exercises the same
 * post-extraction write opportunity as the App Host's npm install command. */
async function installWithHook(mutation: string) {
  const directory = await mkdtemp(join(tmpdir(), 'mh-installed-stack-'))
  directories.push(directory)
  const source = join(directory, 'package')
  const dependency = join(directory, 'dependency')
  const workspace = join(directory, 'app')
  await mkdir(join(source, 'dist'), { recursive: true })
  await mkdir(dependency)
  await mkdir(workspace)
  await writeFile(
    join(source, 'package.json'),
    JSON.stringify({
      name: '@cipherstash/stack',
      version: '1.2.1',
      main: 'dist/index.js',
    }),
  )
  await writeFile(join(source, 'dist/index.js'), 'module.exports="trusted"\n')
  await writeFile(
    join(dependency, 'package.json'),
    JSON.stringify({
      name: 'integrity-hook-fixture',
      version: '1.0.0',
      scripts: { postinstall: 'node hook.cjs' },
    }),
  )
  await writeFile(
    join(dependency, 'hook.cjs'),
    `const fs = require('node:fs');
const path = require('node:path');
const stack = path.resolve('../@cipherstash/stack');
fs.writeFileSync('../../hook-ran', 'yes');
${mutation}
`,
  )
  const tarball = join(directory, 'resolved-stack.tgz')
  const hookTarball = join(directory, 'dependency.tgz')
  await execute('tar', ['-czf', tarball, '-C', directory, 'package'], {
    env: { ...process.env, COPYFILE_DISABLE: '1' },
  })
  await execute('tar', ['-czf', hookTarball, '-C', directory, 'dependency'], {
    env: { ...process.env, COPYFILE_DISABLE: '1' },
  })
  await writeFile(
    join(workspace, 'package.json'),
    JSON.stringify({
      name: 'app-fixture',
      version: '1.0.0',
      dependencies: { 'integrity-hook-fixture': `file:${hookTarball}` },
      // npm 12 requires actor-owned approval; npm 10 ignores this field.
      allowScripts: { [`file:${hookTarball}`]: true },
    }),
  )
  await execute(
    'npm',
    [
      'install',
      '--offline',
      '--no-audit',
      '--no-fund',
      '--cache',
      join(directory, 'cache'),
      '--save-exact',
      tarball,
    ],
    { cwd: workspace },
  )
  expect(await readFile(join(workspace, 'hook-ran'), 'utf8')).toBe('yes')
  return { workspace, tarball }
}

test('accepts installed Stack files that match the host tarball after lifecycle hooks', async () => {
  const installed = await installWithHook('')
  await expect(verifyInstalledTarball(installed)).resolves.toBeUndefined()
})

test('permits npm to nest unbundled dependencies separately from Stack package files', async () => {
  const installed = await installWithHook(`
const nested = path.join(stack, 'node_modules/nested-dependency');
fs.mkdirSync(nested, {recursive: true});
fs.writeFileSync(path.join(nested, 'index.js'), 'module.exports="dependency"\\n');`)
  await expect(verifyInstalledTarball(installed)).resolves.toBeUndefined()
})

test.each([
  [
    'changed file',
    `fs.writeFileSync(path.join(stack, 'dist/index.js'), 'module.exports="altered"\\n');`,
  ],
  ['missing file', `fs.unlinkSync(path.join(stack, 'dist/index.js'));`],
  [
    'added file',
    `fs.writeFileSync(path.join(stack, 'injected.js'), 'module.exports="injected"\\n');`,
  ],
  [
    'file replaced by a symlink with matching bytes',
    `const file = path.join(stack, 'dist/index.js');
const target = path.resolve('../../linked-code.js');
fs.copyFileSync(file, target);
fs.unlinkSync(file);
fs.symlinkSync(target, file);`,
  ],
  [
    'package directory replaced by a symlink with matching bytes',
    `fs.renameSync(stack, stack + '-elsewhere');
fs.symlinkSync(stack + '-elsewhere', stack);`,
  ],
  [
    'scope directory replaced by a symlink with matching bytes',
    `const scope = path.dirname(stack);
fs.renameSync(scope, scope + '-elsewhere');
fs.symlinkSync(scope + '-elsewhere', scope);`,
  ],
  [
    'nested dependency directory replaced by a symlink',
    `const target = path.resolve('../../external-dependencies');
fs.mkdirSync(target);
fs.symlinkSync(target, path.join(stack, 'node_modules'));`,
  ],
])('rejects a dependency install hook leaving %s', async (_name, mutation) => {
  const installed = await installWithHook(mutation)
  await expect(verifyInstalledTarball(installed)).rejects.toThrow(
    'Installed Stack is not the resolved tarball',
  )
})

/** Construct one empty ustar entry so unsafe names are not sanitized by the
 * fixture archiver before the verifier sees them. No payload is extracted. */
function archiveEntry(name: string, type: string) {
  const header = Buffer.alloc(512)
  header.write(name, 0)
  header.write('0000644\0', 100)
  header.write('0000000\0', 108)
  header.write('0000000\0', 116)
  header.write('00000000000\0', 124)
  header.write('00000000000\0', 136)
  header.fill(' ', 148, 156)
  header.write(type, 156)
  if (type !== '0') header.write('../../escaped', 157)
  header.write('ustar\0', 257)
  header.write('00', 263)
  const checksum = header.reduce((sum, value) => sum + value, 0)
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148)
  return gzipSync(Buffer.concat([header, Buffer.alloc(1024)]))
}

test.each([
  ['parent traversal', 'package/../../escaped', '0'],
  ['absolute path', '/package/escaped', '0'],
  ['symbolic link', 'package/link', '2'],
  ['hard link', 'package/link', '1'],
])(
  'rejects a trusted-source archive containing %s without extracting it',
  async (_name, entry, type) => {
    const installed = await installWithHook('')
    const bytes = archiveEntry(entry, type)
    await writeFile(installed.tarball, bytes)
    const lockPath = join(installed.workspace, 'package-lock.json')
    const lock = JSON.parse(await readFile(lockPath, 'utf8'))
    lock.packages['node_modules/@cipherstash/stack'].integrity =
      `sha512-${createHash('sha512').update(bytes).digest('base64')}`
    await writeFile(lockPath, JSON.stringify(lock))
    await expect(verifyInstalledTarball(installed)).rejects.toThrow(
      'Installed Stack is not the resolved tarball',
    )
    await expect(
      lstat(join(installed.workspace, '../escaped')),
    ).rejects.toMatchObject({
      code: 'ENOENT',
    })
  },
)
