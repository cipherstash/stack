import { lstat, readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { satisfies, valid } from 'semver'
import ts from 'typescript'
import { noRewrite } from './no-rewrite.mjs'
import { object } from './record.mjs'

export const requiredOracleChecks = [
  'no-rewrite.legacy-bytes',
  'migration.protect-dependencies-absent',
  'migration.protect-ffi-version',
  'migration.endpoint-shim-absent',
  'migration.active-hmac-absent',
]
const legacyPackage =
  /@cipherstash\/(?:protect-dynamodb|protect|schema)(?![\w-])/
const hostSetting = /^(CS_CTS_HOST|CS_ZEROKMS_HOST)$/

/** Compatibility entry point for check-level callers.
 * @param {unknown} before @param {unknown} after @returns {import('../types.js').OracleCheck} */
export function noRewriteCheck(before, after) {
  try {
    return noRewrite(before, after)
  } catch {
    return {
      id: 'no-rewrite.legacy-bytes',
      passed: false,
      cause: 'Legacy snapshot comparison is unavailable',
    }
  }
}

/** Read app-owned files without following links into protected host resources.
 * @param {string} path */
async function textFile(path) {
  const stat = await lstat(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8 * 1024 * 1024)
    throw Error('Migration inspection requires a bounded regular file')
  return readFile(path, 'utf8')
}

/** @param {string} workspace @returns {Promise<Array<{path:string,text:string}>>} */
async function sources(workspace) {
  const result = []
  for (const entry of await readdir(workspace, { withFileTypes: true })) {
    if (['.git', 'node_modules'].includes(entry.name)) continue
    const path = join(workspace, entry.name)
    if (entry.isSymbolicLink())
      throw Error('Migration source symlinks are not supported')
    if (entry.isDirectory()) result.push(...(await sources(path)))
    else if (/\.[cm]?[jt]sx?$/.test(entry.name))
      result.push({ path, text: await textFile(path) })
  }
  return result
}

/** Extract literal module references and endpoint configuration from syntax,
 * excluding comments and documentation mentioning the old package names.
 * @param {{path:string,text:string}[]} files */
function sourceFacts(files) {
  let legacyImport = false,
    endpointShim = false
  for (const { path, text } of files) {
    const tree = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true)
    /** @param {import('typescript').Node} node */
    function visit(node) {
      if (ts.isIdentifier(node) && hostSetting.test(node.text))
        endpointShim = true
      if (ts.isStringLiteralLike(node)) {
        if (hostSetting.test(node.text)) endpointShim = true
        const parent = node.parent
        if (
          ts.isImportDeclaration(parent) ||
          ts.isExportDeclaration(parent) ||
          (ts.isCallExpression(parent) &&
            (parent.expression.kind === ts.SyntaxKind.ImportKeyword ||
              (ts.isIdentifier(parent.expression) &&
                parent.expression.text === 'require')))
        )
          legacyImport ||= legacyPackage.test(node.text)
      }
      ts.forEachChild(node, visit)
    }
    visit(tree)
  }
  return { legacyImport, endpointShim }
}

/** Determine the actual FFI selected for the installed exact Stack package.
 * The range comes from registry metadata captured before the Migrator starts.
 * @param {Record<string,unknown>} lock @param {string} stackVersion @param {string} ffiRange */
function resolvedFfi(lock, stackVersion, ffiRange) {
  const packages = object(lock.packages)
  const stack = object(packages['node_modules/@cipherstash/stack'])
  if (stack.version !== stackVersion)
    throw Error('Installed Stack version does not match the Run')
  const ffi = object(
    packages[
      'node_modules/@cipherstash/stack/node_modules/@cipherstash/protect-ffi'
    ] ?? packages['node_modules/@cipherstash/protect-ffi'],
  )
  if (
    typeof ffi.version !== 'string' ||
    !valid(ffi.version) ||
    ffi.version === '0.18.1' ||
    !satisfies(ffi.version, ffiRange)
  )
    throw Error('Resolved Stack FFI dependency is unavailable')
  return ffi.version
}

/** Reject old or aliased FFI versions anywhere in the migrated npm lockfile.
 * @param {Record<string,unknown>} lock @param {string} expected */
function ffiVersionsMatch(lock, expected) {
  const packages = object(lock.packages)
  const entries = Object.entries(packages).flatMap(([path, raw]) => {
    const pkg = object(raw)
    return path.endsWith('/@cipherstash/protect-ffi') ||
      pkg.name === '@cipherstash/protect-ffi'
      ? [pkg]
      : []
  })
  return entries.length > 0 && entries.every((pkg) => pkg.version === expected)
}

/** @param {Record<string,unknown>} manifest @param {string} expected */
function ffiDeclarationsMatch(manifest, expected) {
  for (const field of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    if (!manifest[field]) continue
    for (const [name, spec] of Object.entries(object(manifest[field]))) {
      if (typeof spec !== 'string') return false
      const alias = spec.match(/^npm:@cipherstash\/protect-ffi@(.+)$/)
      if (name === '@cipherstash/protect-ffi' || alias) {
        try {
          if (!satisfies(expected, alias?.[1] ?? spec)) return false
        } catch {
          return false
        }
      }
    }
  }
  return true
}

/** Check both Migrator output and the installed App Host copy, including changes
 * made by lifecycle scripts; inspect Mutation Data without importing app code.
 * @param {{workspace:string,installedWorkspace:string,stackVersion:string,ffiRange:string,mutationSnapshot?:unknown,procedure?:string}} options
 * @returns {Promise<import('../types.js').OracleCheck[]>} */
export async function migrationChecks({
  workspace,
  installedWorkspace,
  stackVersion,
  ffiRange,
  mutationSnapshot,
  procedure = 'dynamodb',
}) {
  /** @type {import('../types.js').OracleCheck[]} */
  const checks = []
  /** @param {string} id @param {()=>Promise<boolean>|boolean} action */
  async function check(id, action) {
    try {
      const passed = await action()
      checks.push({
        id,
        passed,
        ...(!passed ? { cause: 'Migration requirement is not satisfied' } : {}),
      })
    } catch {
      checks.push({
        id,
        passed: false,
        cause: 'Required migration evidence is unavailable',
      })
    }
  }
  // Inspect the Migrator's output and the App Host's installed copy: install
  // lifecycle scripts run in the installed copy, which is the one that executes.
  const inspected = new Set([workspace, installedWorkspace])
  // One read per check keeps a missing lockfile from hiding the independent shim result.
  await check('migration.protect-dependencies-absent', async () => {
    for (const directory of inspected) {
      const manifest = object(
        JSON.parse(await textFile(join(directory, 'package.json'))),
      )
      const lock = object(
        JSON.parse(await textFile(join(directory, 'package-lock.json'))),
      )
      if (
        legacyPackage.test(JSON.stringify(manifest)) ||
        legacyPackage.test(JSON.stringify(lock)) ||
        sourceFacts(await sources(directory)).legacyImport
      )
        return false
    }
    return true
  })
  await check('migration.protect-ffi-version', async () => {
    const installed = object(
      JSON.parse(await textFile(join(installedWorkspace, 'package-lock.json'))),
    )
    const lock = object(
      JSON.parse(await textFile(join(workspace, 'package-lock.json'))),
    )
    const manifest = object(
      JSON.parse(await textFile(join(workspace, 'package.json'))),
    )
    const installedManifest = object(
      JSON.parse(await textFile(join(installedWorkspace, 'package.json'))),
    )
    const expected = resolvedFfi(installed, stackVersion, ffiRange)
    return (
      ffiVersionsMatch(lock, expected) &&
      ffiVersionsMatch(installed, expected) &&
      ffiDeclarationsMatch(manifest, expected) &&
      ffiDeclarationsMatch(installedManifest, expected)
    )
  })
  await check('migration.endpoint-shim-absent', async () => {
    for (const directory of inspected) {
      if (sourceFacts(await sources(directory)).endpointShim) return false
    }
    return true
  })
  if (procedure === 'dynamodb')
    await check('migration.active-hmac-absent', () => {
      const item = object(object(object(mutationSnapshot).dynamo).Item)
      return (
        Object.hasOwn(item, 'active__source') &&
        !Object.hasOwn(item, 'active__hmac')
      )
    })
  return checks
}
