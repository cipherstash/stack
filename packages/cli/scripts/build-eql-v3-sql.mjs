#!/usr/bin/env node
/**
 * Vendor the EQL v3 SQL bundles into packages/cli/src/sql/.
 *
 * Source of truth: the `cipherstash-encrypt.sql` artifact of the upstream
 * `eql-3.0.0-alpha.2` release (cipherstash/encrypt-query-language), vendored
 * byte-for-byte at
 * packages/stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql.
 * To re-vendor: download the release asset, replace the fixture, re-run this
 * script, and record the new release tag here.
 *
 * Outputs:
 *   - cipherstash-encrypt-v3.sql           — full bundle, byte-identical copy
 *   - cipherstash-encrypt-v3-supabase.sql  — Supabase variant with the
 *     `CREATE OPERATOR CLASS`/`FAMILY` chunks removed (they need superuser,
 *     which Supabase does not grant)
 *
 * The Supabase variant is still derived locally because upstream ships no
 * Supabase variant for v3 yet. The strip mirrors the upstream build's
 * `**\/*operator_class.sql` exclusion glob: the monolith annotates every
 * constituent file with a `--! @file <path>` marker, so the variant drops each
 * `--! @file .../operator_class.sql` chunk up to the next `--! @file` marker.
 *
 * Usage: node packages/cli/scripts/build-eql-v3-sql.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const source = resolve(
  here,
  '../../stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql',
)
const outDir = resolve(here, '../src/sql')

const FILE_MARKER = /^--! @file (.+)$/
const EXCLUDE = /operator_class\.sql$/

function stripOperatorClassChunks(sql) {
  // \r?\n: a CRLF-checked-out source would otherwise defeat the `$`-anchored
  // EXCLUDE match (belt-and-braces — the removedChunks assertion below would
  // still catch it loudly).
  const lines = sql.split(/\r?\n/)
  const out = []
  let skipping = false
  let removedChunks = 0

  for (const line of lines) {
    const marker = line.match(FILE_MARKER)
    if (marker) {
      skipping = EXCLUDE.test(marker[1])
      if (skipping) removedChunks++
    }
    if (!skipping) out.push(line)
  }

  // Verified against eql-3.0.0-alpha.2: exactly 2 `--! @file .../operator_class.sql`
  // chunks (v3/sem/ore_cllw and v3/sem/ore_block_256), together carrying all
  // 4 CREATE OPERATOR CLASS/FAMILY statements in the bundle. The OPE path
  // (ope_cllw) ships no opclass. Hard-coded so layout drift fails loudly.
  if (removedChunks !== 2) {
    throw new Error(
      `Expected to remove exactly 2 operator_class chunks, removed ${removedChunks} — the bundle layout changed; review the strip logic.`,
    )
  }

  const stripped = out.join('\n')
  if (/CREATE OPERATOR (CLASS|FAMILY)/.test(stripped)) {
    throw new Error(
      'Stripped bundle still contains CREATE OPERATOR CLASS/FAMILY statements.',
    )
  }

  return stripped
}

const sql = readFileSync(source, 'utf8')

// Companion drift check: the full bundle must carry exactly the 4
// CREATE OPERATOR CLASS/FAMILY statements the 2 stripped chunks account for
// (verified against eql-3.0.0-alpha.2). An opclass appearing outside an
// operator_class.sql chunk would otherwise slip into the Supabase variant
// (the post-strip scan below also guards that; this pins the source shape).
const opclassStatements = sql.match(/CREATE OPERATOR (CLASS|FAMILY)/g) ?? []
if (opclassStatements.length !== 4) {
  throw new Error(
    `Expected the source bundle to contain exactly 4 CREATE OPERATOR CLASS/FAMILY statements, found ${opclassStatements.length} — the bundle layout changed; review the strip logic.`,
  )
}

writeFileSync(resolve(outDir, 'cipherstash-encrypt-v3.sql'), sql)
writeFileSync(
  resolve(outDir, 'cipherstash-encrypt-v3-supabase.sql'),
  stripOperatorClassChunks(sql),
)

console.log(
  'Wrote cipherstash-encrypt-v3.sql and cipherstash-encrypt-v3-supabase.sql',
)
