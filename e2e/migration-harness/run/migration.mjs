import { lstat, readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { satisfies } from 'semver'

const legacy = [
  '@cipherstash/protect',
  '@cipherstash/protect-dynamodb',
  '@cipherstash/schema',
]
/** Static inspection never imports application code.
 * @param {{workspace:string,activeItem:unknown,stackVersion:string}} options
 * @returns {Promise<import('../types.js').OracleCheck[]>} */
export async function migrationChecks({ workspace, activeItem, stackVersion }) {
  /** @type {import('../types.js').OracleCheck[]} */
  const checks = []
  /** @param {string} id @param {()=>Promise<void>} action */
  async function check(id, action) {
    try {
      await action()
      checks.push({ id, passed: true })
    } catch (error) {
      checks.push({
        id,
        passed: false,
        cause: error instanceof Error ? error.message : String(error),
      })
    }
  }
  /** @param {string} name */
  async function json(name) {
    const path = join(workspace, name)
    if (!(await lstat(path)).isFile())
      throw Error(`Not a regular file: ${name}`)
    return JSON.parse(await readFile(path, 'utf8'))
  }
  await check('migration.legacy-packages-absent', async () => {
    const manifest = await json('package.json')
    const lock = await json('package-lock.json')
    const packages = lock.packages
    if (!packages || typeof packages !== 'object')
      throw Error('Expected npm lockfile packages')
    for (const name of legacy) {
      if (
        [
          'dependencies',
          'devDependencies',
          'optionalDependencies',
          'peerDependencies',
        ].some((kind) => name in (manifest[kind] ?? {})) ||
        Object.keys(packages).some((path) =>
          path.endsWith(`node_modules/${name}`),
        )
      )
        throw Error(`Legacy package remains: ${name}`)
    }
    const stack = packages['node_modules/@cipherstash/stack']
    if (stack?.version !== stackVersion)
      throw Error('Installed Stack differs from resolved Stack')
    const ffiRange = stack.dependencies?.['@cipherstash/protect-ffi']
    if (typeof ffiRange !== 'string')
      throw Error('Resolved Stack has no FFI dependency')
    for (const [path, value] of Object.entries(packages)) {
      if (!path.endsWith('node_modules/@cipherstash/protect-ffi')) continue
      const version = Object(value).version
      if (
        version === '0.18.1' ||
        typeof version !== 'string' ||
        !satisfies(version, ffiRange)
      )
        throw Error('Legacy or incompatible FFI remains')
    }
  })
  await check('migration.legacy-source-absent', async () => {
    /** @param {string} directory */
    async function scan(directory) {
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        if (['node_modules', '.git'].includes(entry.name)) continue
        const path = join(directory, entry.name)
        if (entry.isSymbolicLink())
          throw Error('Application source must not contain symbolic links')
        if (entry.isDirectory()) await scan(path)
        else if (/\.[cm]?[jt]sx?$/.test(entry.name)) {
          const source = await readFile(path, 'utf8')
          if (
            legacy.some(
              (name) =>
                source.includes(`'${name}'`) || source.includes(`"${name}"`),
            )
          )
            throw Error('Legacy package import remains')
          if (/CS_(?:CTS|ZEROKMS)_HOST/.test(source))
            throw Error('Legacy endpoint shim remains')
        }
      }
    }
    await scan(workspace)
  })
  await check('migration.active-hmac-absent', async () => {
    if (
      !activeItem ||
      typeof activeItem !== 'object' ||
      !('active__source' in activeItem)
    )
      throw Error('Updated Mutation Data missing')
    if ('active__hmac' in activeItem)
      throw Error('Legacy boolean equality term remains after setActive')
  })
  return checks
}
