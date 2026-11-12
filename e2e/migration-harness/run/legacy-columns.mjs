/** The Fixture App's Legacy Data columns, as the harness checks them. The
 * harness never imports app code, so `fixture/src/stores.mjs` keeps its own
 * copy; every harness site reads this one.
 * `notes` is free text with no lookup, so it has no HMAC term. */
export const dynamoColumns = /** @type {const} */ ([
  'email',
  'emailLower',
  'age',
  'balance',
  'active',
  'notes',
])
export const postgresColumns = /** @type {const} */ (['email', 'age', 'notes'])

/** @param {string} column */
export function hasHmac(column) {
  return column !== 'notes'
}

/** The Oracle's Legacy Data read. Column names are the constants above; only
 * the key is a parameter. */
export const postgresSnapshotQuery = `SELECT pk, ${postgresColumns
  .map((column) => `"${column}"::jsonb`)
  .join(', ')} FROM customers WHERE pk = $1`
