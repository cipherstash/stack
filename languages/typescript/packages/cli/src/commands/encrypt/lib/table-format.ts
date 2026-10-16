/**
 * Render rows of string cells as an aligned, two-space-separated text table
 * with a header row. Shared by `stash encrypt status` and `stash decrypt
 * status` so the two read alike.
 *
 * `headers` fixes both the column order and the header labels; every row must
 * carry the same keys.
 */
export function formatTable<K extends string>(
  headers: Readonly<Record<K, string>>,
  rows: ReadonlyArray<Readonly<Record<K, string>>>,
): string {
  const keys = Object.keys(headers) as K[]
  const all = [headers, ...rows]
  const widths = new Map<K, number>(keys.map((key) => [key, 0]))
  for (const row of all) {
    for (const key of keys) {
      widths.set(key, Math.max(widths.get(key) ?? 0, row[key].length))
    }
  }
  return all
    .map((row) =>
      keys.map((key) => row[key].padEnd(widths.get(key) ?? 0)).join('  '),
    )
    .join('\n')
}
