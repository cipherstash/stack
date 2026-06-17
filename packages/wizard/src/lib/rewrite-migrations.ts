import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

/**
 * Matches drizzle-kit's generated in-place type change to the encrypted
 * column type. drizzle-kit's ALTER COLUMN path wraps the customType
 * `dataType()` return value in double-quotes and prepends `"{typeSchema}".`.
 * Custom types have no `typeSchema`, so we see several mangled forms
 * depending on what `dataType()` returned. We match all of them:
 *
 * - bare `eql_v2_encrypted` → `"undefined"."eql_v2_encrypted"`
 * - pre-quoted `"public"."eql_v2_encrypted"` (stack 0.15.0 regression) →
 *   `"undefined".""public"."eql_v2_encrypted""`
 * - the plain `eql_v2_encrypted` and `"public"."eql_v2_encrypted"` forms,
 *   in case a future drizzle-kit release stops prepending undefined.
 *
 * Captures:
 * - $1: table name (without quotes)
 * - $2: column name (without quotes)
 *
 * Note: a copy of this lives in `stash` (`db/rewrite-migrations.ts`)
 * because cli's `db install --drizzle` uses the same fix. Both copies are
 * tightly coupled to drizzle-kit's output format — if drizzle-kit changes,
 * both need to be updated together.
 */
const ALTER_COLUMN_TO_ENCRYPTED_RE =
  /ALTER TABLE "([^"]+)"\s+ALTER COLUMN "([^"]+)"\s+SET DATA TYPE (?:"undefined"\.""public"\."eql_v2_encrypted""|"undefined"\."eql_v2_encrypted"|"public"\."eql_v2_encrypted"|eql_v2_encrypted)[^;]*;/gi

/**
 * Replace in-place `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted` statements
 * with an ADD + DROP + RENAME sequence.
 *
 * **Why this exists (CIP-2991, CIP-2994):** Postgres has no implicit cast from
 * `text`/`numeric` to `eql_v2_encrypted`, so `ALTER COLUMN ... SET DATA TYPE
 * eql_v2_encrypted` fails with `cannot cast type ... to eql_v2_encrypted`.
 * The fix that works on both empty and non-empty tables is to add a new
 * encrypted column, backfill it, drop the original, and rename the new
 * column into place. For empty tables the UPDATE is a no-op and the
 * sequence is effectively equivalent to DROP+ADD.
 *
 * We only rewrite the statement — the actual encryption of existing rows has
 * to happen in application code (via `encryptModel` from
 * `@cipherstash/stack`), which is why the UPDATE is emitted as a guidance
 * comment rather than real SQL. Running this migration against a populated
 * table leaves the new column NULL until the app backfills it.
 */
export async function rewriteEncryptedAlterColumns(
  outDir: string,
  options: { skip?: string } = {},
): Promise<string[]> {
  const entries = await readdir(outDir).catch(() => [])
  const rewritten: string[] = []

  for (const entry of entries) {
    if (!entry.endsWith('.sql')) continue
    const filePath = join(outDir, entry)
    if (options.skip && filePath === options.skip) continue

    const original = await readFile(filePath, 'utf-8')
    if (!ALTER_COLUMN_TO_ENCRYPTED_RE.test(original)) continue

    // Reset the regex's lastIndex — it's stateful on /g
    ALTER_COLUMN_TO_ENCRYPTED_RE.lastIndex = 0

    const updated = original.replace(
      ALTER_COLUMN_TO_ENCRYPTED_RE,
      (_match, table: string, column: string) => renderSafeAlter(table, column),
    )

    if (updated !== original) {
      await writeFile(filePath, updated, 'utf-8')
      rewritten.push(filePath)
    }
  }

  return rewritten
}

function renderSafeAlter(table: string, column: string): string {
  const tmp = `${column}__cipherstash_tmp`
  return [
    '-- Rewritten by @cipherstash/wizard: in-place ALTER COLUMN cannot cast to',
    `-- eql_v2_encrypted. If "${table}" already has rows, backfill the new`,
    "-- column via @cipherstash/stack's encryptModel in application code BEFORE",
    '-- running this migration in production. Empty tables are safe as-is.',
    `ALTER TABLE "${table}" ADD COLUMN "${tmp}" "public"."eql_v2_encrypted";`,
    `-- UPDATE "${table}" SET "${tmp}" = /* encrypted value for ${column} */ NULL;`,
    `ALTER TABLE "${table}" DROP COLUMN "${column}";`,
    `ALTER TABLE "${table}" RENAME COLUMN "${tmp}" TO "${column}";`,
  ].join('\n')
}
