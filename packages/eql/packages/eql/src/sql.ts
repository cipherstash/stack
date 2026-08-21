import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { releaseManifest } from './generated/release-manifest'

export interface EqlReleaseManifest {
  eqlVersion: string
  schemaVersion: 3
  installSqlSha256: string
  uninstallSqlSha256: string
}

declare const __dirname: string | undefined

const here =
  typeof __dirname === 'string'
    ? __dirname
    : dirname(fileURLToPath(import.meta.url))

const sqlDir = existsSync(join(here, 'sql'))
  ? join(here, 'sql')
  : join(here, '..', 'sql')

export { releaseManifest }

export function installSqlPath(): string {
  return join(sqlDir, 'cipherstash-encrypt.sql')
}

export function uninstallSqlPath(): string {
  return join(sqlDir, 'cipherstash-encrypt-uninstall.sql')
}

export function readInstallSql(): string {
  return readSqlFile(installSqlPath())
}

export function readUninstallSql(): string {
  return readSqlFile(uninstallSqlPath())
}

function readSqlFile(path: string): string {
  if (!existsSync(path)) {
    throw new Error(`EQL SQL asset is missing from package: ${path}`)
  }
  return readFileSync(path, 'utf8')
}
