import { existsSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import { installSqlPath, readInstallSql, releaseManifest, uninstallSqlPath } from './sql'

describe('@cipherstash/eql SQL assets', () => {
  test('release manifest shape is stable', () => {
    expect(releaseManifest.schemaVersion).toBe(3)
    expect(releaseManifest).toHaveProperty('eqlVersion')
    expect(releaseManifest).toHaveProperty('installSqlSha256')
    expect(releaseManifest).toHaveProperty('uninstallSqlSha256')
  })

  test('SQL path helpers point at packaged filenames', () => {
    expect(installSqlPath()).toMatch(/cipherstash-encrypt\.sql$/)
    expect(uninstallSqlPath()).toMatch(/cipherstash-encrypt-uninstall\.sql$/)
  })

  test('readInstallSql reads prepared assets, the DEV placeholder, or fails clearly', () => {
    // Three valid states: no bundled SQL yet (throws), the committed DEV
    // placeholder (before `release:prepare_bindings_assets`), or real
    // exact-version SQL (after prep, e.g. in the publish workflow). The
    // release manifest is the deterministic signal for which state we're in.
    if (!existsSync(installSqlPath())) {
      expect(() => readInstallSql()).toThrow(/EQL SQL asset is missing/)
      return
    }
    const sql = readInstallSql()
    if (releaseManifest.eqlVersion === 'DEV') {
      expect(sql).toContain('DEV placeholder')
    } else {
      expect(sql).toContain('eql_v3')
    }
  })
})
