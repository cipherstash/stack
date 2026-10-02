import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

/**
 * One migration as drizzle-kit records it in `meta/_journal.json`.
 *
 * Only the two fields the applied-state check needs are modelled. `when` is the
 * generation timestamp in epoch milliseconds — drizzle names it `folderMillis`
 * once it reaches the migrator, and it is the value written into
 * `drizzle.__drizzle_migrations.created_at` on a successful apply.
 */
export interface JournalEntry {
  /** Migration tag, e.g. `0001_encrypt-email`. The `.sql` file is `<tag>.sql`. */
  tag: string
  /** Generation timestamp in epoch milliseconds (`folderMillis`). */
  when: number
}

/** Thrown when the journal is absent or unreadable as a drizzle journal. */
export class JournalError extends Error {}

/** `<outDir>/meta/_journal.json` — drizzle-kit's fixed location. */
export function journalPath(outDir: string): string {
  return join(outDir, 'meta', '_journal.json')
}

/**
 * Read drizzle-kit's migration journal.
 *
 * Throws a {@link JournalError} when the file is missing, unparseable, or does
 * not carry an `entries` array. Every one of those means the caller cannot tell
 * which migrations exist or when they were generated, and a repair that cannot
 * answer that must refuse rather than guess.
 */
export async function readJournal(outDir: string): Promise<JournalEntry[]> {
  const path = journalPath(outDir)
  let raw: string
  try {
    raw = await readFile(path, 'utf-8')
  } catch (error) {
    throw new JournalError(
      `Could not read ${path}: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    throw new JournalError(
      `Could not parse ${path}: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as { entries?: unknown }).entries)
  ) {
    throw new JournalError(`${path} has no "entries" array.`)
  }

  const entries: JournalEntry[] = []
  for (const entry of (parsed as { entries: unknown[] }).entries) {
    if (typeof entry !== 'object' || entry === null) continue
    const { tag, when } = entry as { tag?: unknown; when?: unknown }
    // A malformed individual entry is not a malformed journal: skip it rather
    // than abort, so one bad row cannot block repairing the rest. It simply
    // never matches a file, and an unmatched file is treated as unapplied.
    if (typeof tag !== 'string' || typeof when !== 'number') continue
    entries.push({ tag, when })
  }
  return entries
}
