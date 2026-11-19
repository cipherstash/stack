import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { access, cp, lstat, open, readdir, readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
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

/** @typedef {{size:number,digest:string}|null} PackageEntry */

/** Read the trusted artifact without extracting anything onto the host. Reject
 * links, special entries and ambiguous paths before reading any file payload.
 * @param {string} tarball
 * @returns {Promise<Map<string,PackageEntry>>} */
async function tarballContents(tarball) {
  const exec = promisify(execFile)
  const listing = await exec('tar', ['-tf', tarball], {
    maxBuffer: 8 * 1024 * 1024,
  })
  const details = await exec('tar', ['-tvf', tarball], {
    maxBuffer: 8 * 1024 * 1024,
  })
  const names = listing.stdout.trimEnd().split('\n')
  const types = details.stdout
    .trimEnd()
    .split('\n')
    .map((line) => line[0])
  if (names.length !== types.length)
    throw Error('Unsupported Stack tarball entries')
  /** @type {Map<string,PackageEntry>} */
  const contents = new Map([['', null]])
  const listed = new Set()
  for (const [index, name] of names.entries()) {
    const path = name.replace(/\/$/, '')
    const parts = path.split('/')
    if (
      !['-', 'd'].includes(types[index]) ||
      parts.shift() !== 'package' ||
      parts.some((part) => !part || part === '.' || part === '..') ||
      /[\\*?[\]]/.test(path) ||
      [...path].some(
        (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
      ) ||
      listed.has(path)
    )
      throw Error('Unsupported Stack tarball entries')
    listed.add(path)
    const relative = parts.join('/')
    for (let depth = 1; depth < parts.length; depth++) {
      const parent = parts.slice(0, depth).join('/')
      if (contents.has(parent) && contents.get(parent) !== null)
        throw Error('Unsupported Stack tarball entries')
      contents.set(parent, null)
    }
    if (types[index] === 'd') {
      if (contents.has(relative) && contents.get(relative) !== null)
        throw Error('Unsupported Stack tarball entries')
      contents.set(relative, null)
    } else {
      if (!relative || contents.has(relative))
        throw Error('Unsupported Stack tarball entries')
      // A bounded artifact read; installed actor-written files are streamed below.
      const result = await exec('tar', ['-xOf', tarball, name], {
        encoding: 'buffer',
        maxBuffer: 64 * 1024 * 1024,
      })
      contents.set(relative, {
        size: result.stdout.length,
        digest: createHash('sha512').update(result.stdout).digest('hex'),
      })
    }
  }
  return contents
}

/** Check installed files against trusted paths, types, sizes and content hashes.
 * npm may place unbundled transitive dependencies in root node_modules, outside
 * this package artifact. A bundled node_modules tree is checked normally.
 * @param {string} directory @param {Map<string,PackageEntry>} expected */
async function verifyPackageContents(directory, expected) {
  const seen = new Set()
  /** @param {string} path @param {string} relative */
  async function visit(path, relative) {
    const stat = await lstat(path)
    const entry = expected.get(relative)
    if (stat.isDirectory()) {
      if (relative === 'node_modules' && !expected.has(relative)) return
      if (entry !== null) throw Error('Unexpected installed Stack directory')
      seen.add(relative)
      for (const name of await readdir(path))
        await visit(join(path, name), relative ? `${relative}/${name}` : name)
      return
    }
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      !entry ||
      stat.size !== entry.size
    )
      throw Error('Unexpected installed Stack file')
    const digest = createHash('sha512')
    let bytes = 0
    const handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    )
    try {
      for await (const chunk of handle.createReadStream({ autoClose: false })) {
        bytes += chunk.length
        if (bytes > entry.size)
          throw Error('Installed Stack file grew during verification')
        digest.update(chunk)
      }
    } finally {
      await handle.close()
    }
    if (bytes !== entry.size || digest.digest('hex') !== entry.digest)
      throw Error('Installed Stack file differs from the tarball')
    seen.add(relative)
  }
  await visit(directory, '')
  if (seen.size !== expected.size)
    throw Error('Installed Stack file is missing')
}

/** Confirm both npm's lock entry and installed Stack files match the host-owned
 * tarball after dependency lifecycle scripts. Expected contents come only from
 * the trusted artifact; actor-written manifests cannot redefine that expectation.
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
  try {
    const expected = await tarballContents(tarball)
    // Check every actor-controlled ancestor, not only the final package path:
    // lstat(package) alone would follow a substituted @cipherstash directory.
    let installed = workspace
    for (const part of ['', 'node_modules', '@cipherstash']) {
      installed = join(installed, part)
      if (!(await lstat(installed)).isDirectory())
        throw Error('Installed Stack is not the resolved tarball')
    }
    await verifyPackageContents(join(installed, 'stack'), expected)
  } catch (cause) {
    throw Error('Installed Stack is not the resolved tarball', { cause })
  }
}
