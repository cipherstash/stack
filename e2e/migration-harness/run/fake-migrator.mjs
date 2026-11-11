import { cp, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

/** Harness-owned deterministic command substitute. The hidden reference is never mounted.
 * @param {{root:string,workspace:string,kind:string,stack:string,procedure?:string}} options
 * @returns {Promise<import("../types.js").MigratorResult & {stdout:string,stderr:string}>} */
export async function fakeMigrate({
  root,
  workspace,
  kind,
  stack,
  procedure = 'dynamodb',
}) {
  const postgres = procedure === 'postgres-v2-to-v3'
  const variants = [
    'reference',
    'downcase',
    'stale-hmac',
    'bigint',
    'rewrite',
    'missing-log',
    'legacy-ffi',
    'noop',
    'denied-app',
    'denied-lifecycle',
  ]
  const postgresVariants = [
    'reference',
    'noop',
    'row-loss',
    'wrong-mapping',
    'fresh-v2',
    'missing-index',
    'rewrite',
    'missing-log',
  ]
  if (!(postgres ? postgresVariants : variants).includes(kind))
    throw Error('Unknown Fake Migrator')
  if (kind !== 'noop') {
    await cp(
      resolve(
        root,
        `e2e/migration-harness/${postgres ? 'postgres-reference' : 'reference'}/src`,
      ),
      resolve(workspace, 'src'),
      { recursive: true },
    )
    const path = resolve(workspace, 'src/app.mjs')
    let source = await readFile(path, 'utf8')
    if (postgres)
      source = source.replace(
        "const variant = 'reference'",
        `const variant = '${kind}'`,
      )
    if (kind === 'denied-app')
      source = `import { readFile } from 'node:fs/promises'\n${source}`.replace(
        'export async function createApp(env = process.env) {',
        'export async function createApp(env = process.env) { await readFile("/trace/canary").catch(() => {});',
      )
    if (kind === 'downcase')
      source = source.replace(
        'emailLower: customer.emailLower.toLowerCase()',
        'emailLower: customer.emailLower',
      )
    if (kind === 'bigint')
      source = source.replace(
        'balance: String(model.balance)',
        'balance: Number(model.balance)',
      )
    if (kind === 'rewrite' && !postgres)
      source = source.replace(
        /get:\s*async\s*\(?pk\)?\s*=>\s*decrypt\(await stores.get\(pk\)\),/,
        'async get(pk) { const value = await decrypt(await stores.get(pk)); if (pk === "legacy" && value) await this.put(value); return value },',
      )
    await writeFile(path, source)
    if (kind === 'stale-hmac') {
      const stores = resolve(workspace, 'src/stores.mjs')
      let text = await readFile(stores, 'utf8')
      text = text.replace(
        'SET active__source = :source REMOVE active__hmac',
        'SET active__source = :source',
      )
      await writeFile(stores, text)
    }
    const manifestPath = resolve(workspace, 'package.json')
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
    for (const group of [
      'dependencies',
      'devDependencies',
      'optionalDependencies',
    ]) {
      for (const name of [
        '@cipherstash/protect',
        '@cipherstash/protect-dynamodb',
        '@cipherstash/schema',
        '@cipherstash/protect-ffi',
      ])
        delete manifest[group]?.[name]
    }
    manifest.dependencies['@cipherstash/stack'] = stack
    if (kind === 'denied-lifecycle')
      manifest.scripts = {
        ...manifest.scripts,
        install: `node -e "try { require('node:fs').readFileSync('/trace/canary') } catch {}"`,
      }
    if (kind === 'legacy-ffi')
      manifest.dependencies['@cipherstash/protect-ffi'] = '0.18.1'
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2))
    // npm must resolve the new graph rather than retain the legacy lock graph.
    await writeFile(resolve(workspace, 'package-lock.json'), '{}')
  }
  if (kind !== 'missing-log')
    await writeFile(resolve(workspace, 'friction.json'), '[]')
  return { exitCode: 0, stdout: `Fake Migrator: ${kind}`, stderr: '' }
}
