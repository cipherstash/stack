/**
 * Quote a PostgreSQL identifier. Doubles any embedded `"` and wraps in `"`.
 * Use for table/column names that cannot be parameterised.
 */
export function quoteIdent(identifier: string): string {
  return `"${identifier.replace(/"/g, '""')}"`
}
