#!/usr/bin/env node
/**
 * Vendor the EQL v3 SQL bundle into packages/cli/src/sql/.
 *
 * Source of truth: the `cipherstash-encrypt.sql` artifact shipped inside the
 * pinned `@cipherstash/eql` npm package (a byte-for-byte copy of the matching
 * GitHub release asset — the package records the artifact's sha256 in its
 * `releaseManifest`, which this script verifies). Bump the `@cipherstash/eql`
 * devDependency and re-run this script to re-vendor.
 *
 * Output:
 *   - cipherstash-encrypt-v3.sql — full bundle, byte-identical copy
 *
 * There is deliberately NO Supabase / no-operator-family variant for v3.
 * Since eql-3.0.0 the bundle installs everywhere with one artifact: its only
 * superuser-requiring statements (the ore_block_256 operator class/family)
 * run inside a DO block that catches `insufficient_privilege` and skips, and
 * a follow-up section disables the ORE-backed encrypted domains when the
 * operator class is absent (CIP-3468). Stripping anything client-side would
 * only defeat that self-adaptation.
 *
 * Usage: node packages/cli/scripts/build-eql-v3-sql.mjs
 */
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const require = createRequire(resolve(here, '../package.json'))

const manifest = require('@cipherstash/eql/package.json')
const sqlEntry = require.resolve('@cipherstash/eql/sql/cipherstash-encrypt.sql')
const sql = readFileSync(sqlEntry, 'utf8')

// Integrity: the package's sql module records the artifact's sha256; verify
// the copy we are about to vendor is exactly that artifact.
const { releaseManifest } = await import('@cipherstash/eql/sql')
const sha = createHash('sha256').update(sql).digest('hex')
if (sha !== releaseManifest.installSqlSha256) {
  throw new Error(
    `@cipherstash/eql install SQL sha mismatch: expected ${releaseManifest.installSqlSha256}, got ${sha}`,
  )
}
if (manifest.version !== releaseManifest.eqlVersion) {
  throw new Error(
    `@cipherstash/eql package/manifest version mismatch: ${manifest.version} vs ${releaseManifest.eqlVersion}`,
  )
}

const outDir = resolve(here, '../src/sql')
writeFileSync(resolve(outDir, 'cipherstash-encrypt-v3.sql'), sql)

console.log(
  `Vendored cipherstash-encrypt-v3.sql from @cipherstash/eql@${manifest.version} (sha256 ${sha})`,
)
