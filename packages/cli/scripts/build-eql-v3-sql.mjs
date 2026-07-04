#!/usr/bin/env node
/**
 * Vendor the EQL v3 SQL bundles into packages/cli/src/sql/.
 *
 * Source of truth: the generated monolith checked in at
 * packages/stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql
 * (itself generated from the upstream encrypt-query-language repo).
 *
 * Outputs:
 *   - cipherstash-encrypt-v3.sql           — full bundle, byte-identical copy
 *   - cipherstash-encrypt-v3-supabase.sql  — Supabase variant with the two
 *     `CREATE OPERATOR CLASS`/`FAMILY` chunks removed (they need superuser,
 *     which Supabase does not grant)
 *
 * The Supabase strip mirrors the upstream build's `**\/*operator_class.sql`
 * exclusion glob: the monolith annotates every constituent file with a
 * `--! @file <path>` marker, so the variant drops each
 * `--! @file .../operator_class.sql` chunk up to the next `--! @file` marker.
 *
 * TEMPORARY vendoring strategy (sync risk): once upstream publishes v3 release
 * artifacts (like the eql-2.x `cipherstash-encrypt[-supabase].sql` assets),
 * regenerate these from the release instead and record the version.
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

writeFileSync(resolve(outDir, 'cipherstash-encrypt-v3.sql'), sql)
writeFileSync(
  resolve(outDir, 'cipherstash-encrypt-v3-supabase.sql'),
  stripOperatorClassChunks(sql),
)

console.log(
  'Wrote cipherstash-encrypt-v3.sql and cipherstash-encrypt-v3-supabase.sql',
)
