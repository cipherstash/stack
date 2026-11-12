import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { access, cp, lstat, readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { promisify } from 'node:util'

/** Resolve once per invocation; Iteration/Loop callers reuse this value.
 * @param {{source:string,root:string,output:string}} options */
export async function resolveStack({ source, root, output }) {
  const exec = promisify(execFile)
  if (source === 'tree' || source.endsWith('.tgz')) {
    let tarball = resolve(source)
    if (source === 'tree') {
      const directory = resolve(root, 'languages/typescript/packages/stack')
      await access(resolve(directory, 'dist/index.js'))
      tarball = resolve(output, 'tree-stack.tgz')
      await exec('pnpm', ['pack', '--out', tarball], { cwd: directory })
    }
    const digest = createHash('sha256')
      .update(await readFile(tarball))
      .digest('hex')
    const result = await exec('tar', ['-xOf', tarball, 'package/package.json'])
    const manifest = JSON.parse(result.stdout)
    if (
      manifest.name !== '@cipherstash/stack' ||
      typeof manifest.version !== 'string'
    )
      throw Error('Tarball is not @cipherstash/stack')
    if (typeof manifest.dependencies?.['@cipherstash/protect-ffi'] !== 'string')
      throw Error('Tarball has no FFI dependency')
    const destination = resolve(output, 'resolved-stack.tgz')
    if (tarball !== destination) await cp(tarball, destination)
    return {
      version: manifest.version,
      ffiRange: manifest.dependencies?.['@cipherstash/protect-ffi'],
      digest,
      tarball: destination,
      install: 'file:./resolved-stack.tgz',
    }
  }
  const result = await exec('npm', [
    'view',
    `@cipherstash/stack@${source}`,
    'version',
    '--json',
  ])
  const resolved = JSON.parse(result.stdout)
  const version = Array.isArray(resolved) ? resolved.at(-1) : resolved
  if (
    typeof version !== 'string' ||
    !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(version)
  )
    throw Error('Could not resolve exact Stack version')
  const ffiAnswer = JSON.parse(
    (
      await exec('npm', [
        'view',
        `@cipherstash/stack@${version}`,
        'dependencies.@cipherstash/protect-ffi',
        '--json',
      ])
    ).stdout,
  )
  // npm 12 wraps even an exact version's field in an array; older npm does not.
  const ffiRange = Array.isArray(ffiAnswer)
    ? ffiAnswer.length === 1
      ? ffiAnswer[0]
      : undefined
    : ffiAnswer
  if (typeof ffiRange !== 'string' || !ffiRange)
    throw Error('Could not resolve Stack FFI dependency')
  return { version, install: version, ffiRange }
}

/** The Subresource Integrity string npm records for a tarball.
 * @param {string} tarball */
async function integrity(tarball) {
  const digest = createHash('sha512')
    .update(await readFile(tarball))
    .digest('base64')
  return `sha512-${digest}`
}

/** Confirm the App Host lockfile records the host-resolved tarball for Stack.
 * The workspace is actor-written, so its lockfile must be a bounded regular file.
 * @param {{workspace:string,tarball:string}} options */
export async function verifyInstalledTarball({ workspace, tarball }) {
  const path = resolve(workspace, 'package-lock.json')
  const stat = await lstat(path)
  if (!stat.isFile() || stat.size > 8 * 1024 * 1024)
    throw Error('Installed Stack is not the resolved tarball')
  let entry
  try {
    entry = JSON.parse(await readFile(path, 'utf8'))?.packages?.[
      'node_modules/@cipherstash/stack'
    ]
  } catch {
    throw Error('Installed Stack is not the resolved tarball')
  }
  if (entry?.integrity !== (await integrity(tarball)))
    throw Error('Installed Stack is not the resolved tarball')
}
