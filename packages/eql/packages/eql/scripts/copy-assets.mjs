import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

export async function copyAssets() {
  const dist = join(packageRoot, 'dist')
  const schemaSrc = join(packageRoot, 'src/generated/schema')
  const sqlSrc = join(packageRoot, 'sql')

  mkdirSync(dist, { recursive: true })

  rmSync(join(dist, 'schema'), { recursive: true, force: true })
  cpSync(schemaSrc, join(dist, 'schema'), { recursive: true })

  rmSync(join(dist, 'sql'), { recursive: true, force: true })
  if (!existsSync(sqlSrc)) {
    throw new Error('packages/eql/sql is missing; run mise run release:prepare_bindings_assets --version <identity> before building a release package')
  }
  cpSync(sqlSrc, join(dist, 'sql'), { recursive: true })
}
