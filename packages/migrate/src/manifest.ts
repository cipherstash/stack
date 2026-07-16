import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { z } from 'zod'

/**
 * The four EQL index kinds recognised by Proxy. Keep in sync with the
 * `indexes` CHECK constraint in `eql_v2_configuration`.
 */
const IndexKind = z.enum(['unique', 'match', 'ore', 'ste_vec'])

/**
 * EQL cast types accepted by the configuration. Validated up front so a
 * typo (`timestampz`, `strnig`) fails at manifest read rather than blowing
 * up much later when the CLI tries to use it.
 */
const CastAs = z.enum([
  'text',
  'int',
  'small_int',
  'big_int',
  'real',
  'double',
  'boolean',
  'date',
  'jsonb',
  'json',
  'float',
  'decimal',
  'timestamp',
])

/**
 * Intent for a single column within the manifest. Expresses *what the user
 * wants the state of this column to be*, not the observed reality — the
 * `status` / `plan` commands diff this against `cs_migrations` and EQL to
 * surface drift.
 */
const ManifestColumnSchema = z.object({
  /** Physical column name, e.g. `email`. */
  column: z.string(),
  /**
   * EQL cast type. Text by default. See the EQL docs for the full list
   * (`text | int | small_int | big_int | real | double | boolean | date |
   * jsonb | json | float | decimal | timestamp`).
   */
  castAs: CastAs.default('text'),
  /** Desired EQL index set. Driver of the `indexes: {…}` block in EQL config. */
  indexes: z.array(IndexKind).default([]),
  /**
   * The phase the user wants this column to reach. `cut-over` is the
   * typical end state (reads transparently decrypted); advance to
   * `dropped` only once you're confident the plaintext column is no
   * longer needed.
   */
  targetPhase: z
    .enum(['schema-added', 'dual-writing', 'backfilled', 'cut-over', 'dropped'])
    .default('cut-over'),
  /**
   * Override for primary-key detection during backfill. Omit to let the
   * CLI auto-detect via `information_schema`.
   */
  pkColumn: z.string().optional(),
  /**
   * The EQL version of the encrypted target column, recorded at backfill
   * time from `detectColumnEqlVersion`. Lets `encrypt status`/`plan`
   * branch without a DB round-trip: v3 columns have no
   * `eql_v2_configuration` registration and no rename cut-over, so the
   * v2-specific drift flags don't apply. Absent on manifests written
   * before v3 support — those columns are necessarily v2.
   */
  eqlVersion: z.union([z.literal(2), z.literal(3)]).optional(),
})

/**
 * Root manifest shape. Stored at `.cipherstash/migrations.json`. Versioned
 * (currently `1`) so we can evolve it without breaking existing manifests.
 */
const ManifestSchema = z.object({
  version: z.literal(1).default(1),
  /** Map of table name → array of column intents for that table. */
  tables: z.record(z.array(ManifestColumnSchema)),
})

export type Manifest = z.infer<typeof ManifestSchema>
export type ManifestColumn = z.infer<typeof ManifestColumnSchema>

/** Canonical on-disk location for the manifest. */
export function manifestPath(cwd: string = process.cwd()): string {
  return path.join(cwd, '.cipherstash', 'migrations.json')
}

/**
 * Read and validate the manifest. Returns `null` when no manifest file
 * exists (this is not an error — most commands still work without one;
 * they just can't show intent-vs-observed drift).
 *
 * Throws on schema validation failures (zod errors).
 */
export async function readManifest(
  cwd: string = process.cwd(),
): Promise<Manifest | null> {
  const filePath = manifestPath(cwd)
  let raw: string
  try {
    raw = await fs.readFile(filePath, 'utf-8')
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw err
  }
  const parsed = ManifestSchema.parse(JSON.parse(raw))
  return parsed
}

/**
 * Validate and write the manifest to `.cipherstash/migrations.json`,
 * creating the directory if it doesn't exist. Rewrites the file
 * atomically-enough for config purposes; not safe under concurrent writers.
 */
export async function writeManifest(
  manifest: Manifest,
  cwd: string = process.cwd(),
): Promise<void> {
  const filePath = manifestPath(cwd)
  await fs.mkdir(path.dirname(filePath), { recursive: true })
  const validated = ManifestSchema.parse(manifest)
  await fs.writeFile(
    filePath,
    `${JSON.stringify(validated, null, 2)}\n`,
    'utf-8',
  )
}

/**
 * Read the manifest, upsert a single column entry under the named table,
 * and write it back. If no manifest exists, creates one. If the column
 * already exists for the table, the existing entry is replaced with the
 * supplied values — useful for keeping the intent in lockstep with what
 * the lifecycle commands actually committed.
 *
 * Called by `stash encrypt backfill` on first run for a column so the
 * intent leg of the three-source state model exists in the repo. The
 * agent (or the user) is free to hand-edit the file later — re-running
 * `backfill` won't clobber a column the user has annotated, only the
 * fields this function controls.
 */
export async function upsertManifestColumn(
  table: string,
  column: ManifestColumn,
  cwd: string = process.cwd(),
): Promise<void> {
  const existing = (await readManifest(cwd)) ?? { version: 1, tables: {} }
  const tableColumns = existing.tables[table] ?? []
  const remaining = tableColumns.filter((c) => c.column !== column.column)
  existing.tables[table] = [...remaining, column]
  await writeManifest(existing, cwd)
}

/**
 * Update just the `targetPhase` of an existing column entry. No-op if
 * the column isn't tracked yet — used by `stash encrypt drop` to bump
 * the intent forward when the user commits to removing the plaintext
 * column entirely.
 */
export async function setManifestTargetPhase(
  table: string,
  columnName: string,
  targetPhase: ManifestColumn['targetPhase'],
  cwd: string = process.cwd(),
): Promise<void> {
  const existing = await readManifest(cwd)
  if (!existing) return
  const tableColumns = existing.tables[table]
  if (!tableColumns) return
  const current = tableColumns.find((c) => c.column === columnName)
  if (!current) return
  existing.tables[table] = tableColumns.map((c) =>
    c.column === columnName ? { ...c, targetPhase } : c,
  )
  await writeManifest(existing, cwd)
}
