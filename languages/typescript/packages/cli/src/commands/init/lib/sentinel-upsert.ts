/**
 * Managed-block upsert for files that we co-own with the user.
 *
 * The sentinel pair lets us re-run `stash init` and replace only our managed
 * region, leaving anything the user wrote outside the sentinels alone.
 *
 *   <!-- cipherstash:rulebook start -->
 *   ...managed content...
 *   <!-- cipherstash:rulebook end -->
 */

const START = '<!-- cipherstash:rulebook start -->'
const END = '<!-- cipherstash:rulebook end -->'

export interface UpsertOptions {
  /** Existing file contents, or undefined when the file does not yet exist. */
  existing?: string
  /** New content to put between the sentinels. Trailing newline normalised. */
  managed: string
}

/**
 * Insert or replace the managed block.
 *
 * - File missing → return managed content wrapped in sentinels.
 * - Sentinel pair found → replace what is between them.
 * - Sentinels missing but file exists → append the managed block, separated by
 *   a blank line so we never collide with the user's last paragraph.
 * - Mismatched sentinels (only start, only end, or end before start) → throw.
 *   Surfacing this loudly is better than silently mangling the file.
 */
export function upsertManagedBlock({
  existing,
  managed,
}: UpsertOptions): string {
  const block = `${START}\n${managed.replace(/\s+$/, '')}\n${END}\n`

  if (existing === undefined || existing.length === 0) {
    return block
  }

  const startIdx = existing.indexOf(START)
  const endIdx = existing.indexOf(END)

  if (startIdx === -1 && endIdx === -1) {
    const sep = existing.endsWith('\n') ? '\n' : '\n\n'
    return `${existing}${sep}${block}`
  }

  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
    throw new Error(
      'cipherstash:rulebook sentinel pair is malformed. Refusing to overwrite. ' +
        'Remove the leftover sentinel manually and re-run.',
    )
  }

  const before = existing.slice(0, startIdx)
  const after = existing.slice(endIdx + END.length)
  // Drop a single leading newline on `after` to avoid double-blank lines.
  const tail = after.startsWith('\n') ? after.slice(1) : after
  return `${before}${block}${tail}`
}

export const SENTINEL_START = START
export const SENTINEL_END = END
