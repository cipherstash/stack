import { readInstallSql } from '@cipherstash/eql/sql'
import { assertBundledEqlSqlDigest } from './bundle-digest.js'

/** Schemas in which the pinned EQL bundle can resolve pgcrypto safely. */
export const SUPPORTED_PGCRYPTO_SCHEMAS = ['extensions', 'public']

/**
 * Read the pinned EQL installer and prove its bytes match the resolved release.
 * Keep this file free of installer and verifier imports: both consume the same
 * artifact, and neither should become the other's dependency.
 */
export function loadBundledEqlSql(): string {
  let sql: string
  try {
    sql = readInstallSql()
  } catch (error) {
    throw new Error(
      'Failed to read the EQL v3 install SQL from `@cipherstash/eql`. Reinstall dependencies (the package ships the bundle in `dist/sql/`).',
      { cause: error },
    )
  }
  return assertBundledEqlSqlDigest(sql)
}
