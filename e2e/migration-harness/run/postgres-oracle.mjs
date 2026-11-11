import { isDeepStrictEqual } from 'node:util'

const columns = ['email', 'age', 'notes']
const targetTypes = ['eql_v3_text_eq', 'eql_v3_integer_eq', 'eql_v3_text']

/** @param {unknown} value @returns {Record<string, unknown>} */
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw Error('Invalid PostgreSQL snapshot object')
  return Object.fromEntries(Object.entries(value))
}

/** Invalid migrated values are failed Oracle evidence, not setup exceptions.
 * @param {unknown} value @returns {Record<string, unknown>} */
function migratedPayload(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : {}
}

/** @param {unknown} snapshot */
function read(snapshot) {
  const data = object(snapshot)
  if (!Array.isArray(data.rows) || !Array.isArray(data.indexes))
    throw Error('Missing PostgreSQL snapshot rows or indexes')
  /** @type {Map<string, Record<string, unknown>>} */
  const rows = new Map()
  for (const raw of data.rows) {
    const row = object(raw)
    if (typeof row.pk !== 'string' || !row.pk || rows.has(row.pk))
      throw Error('Invalid or duplicate PostgreSQL snapshot identity')
    rows.set(row.pk, row)
  }
  return {
    rows,
    columns: object(data.columns),
    indexes: data.indexes.map(object),
  }
}

/** The guide supports these three exact legacy mappings. Validate evidence before
 * allowing a Migrator to change either independent Store Set.
 * @param {unknown} snapshot */
export function validatePostgresBaseline(snapshot) {
  const data = read(snapshot)
  if (!data.rows.size) throw Error('PostgreSQL baseline has no Legacy Data')
  for (const column of columns) {
    if (data.columns[column] !== 'eql_v2_encrypted')
      throw Error(`Unexpected legacy PostgreSQL domain: ${column}`)
    for (const row of data.rows.values()) {
      const payload = object(row[column])
      const identity = object(payload.i)
      if (
        payload.v !== 2 ||
        payload.k !== 'ct' ||
        identity.t !== 'customers' ||
        identity.c !== column ||
        typeof payload.c !== 'string' ||
        !payload.c ||
        (column === 'notes'
          ? payload.hm != null
          : typeof payload.hm !== 'string') ||
        payload.ob != null ||
        payload.bf != null
      )
        throw Error(`Invalid legacy PostgreSQL payload: ${column}`)
    }
  }
}

/** Compare only bytes proven retained by the guide. Version and envelope fields
 * legitimately change; source columns, ciphertext and equality terms must remain.
 * Snapshotting runs with the harness's admin connection, never inside App Host.
 * @param {unknown} before @param {unknown} after
 * @returns {import('../types.js').OracleCheck[]} */
export function postgresMigrationChecks(before, after) {
  validatePostgresBaseline(before)
  const baseline = read(before)
  const current = read(after)
  const sameRows =
    baseline.rows.size === current.rows.size &&
    [...baseline.rows.keys()].every((pk) => current.rows.has(pk))
  const changed = []
  let mapped = columns.every(
    (column, index) =>
      current.columns[column] === 'eql_v2_encrypted' &&
      current.columns[`${column}_v3`] === targetTypes[index],
  )
  for (const [pk, row] of baseline.rows) {
    const actual = current.rows.get(pk)
    for (const column of columns) {
      const source = object(row[column])
      for (const name of [column, `${column}_v3`]) {
        const value = migratedPayload(actual?.[name])
        if (value.c !== source.c || (value.hm ?? null) !== (source.hm ?? null))
          changed.push(`${pk}/${name}`)
      }
      const target = migratedPayload(actual?.[`${column}_v3`])
      if (target.v !== 3 || !isDeepStrictEqual(target.i, source.i))
        mapped = false
    }
  }
  const indexed = ['email', 'age'].every((column) =>
    current.indexes.some(
      (index) =>
        index.expression === `eql_v3.eq_term(${column}_v3)` &&
        index.valid === true &&
        index.ready === true &&
        index.partial === false &&
        index.method === 'btree',
    ),
  )
  return [
    {
      id: 'behaviour.postgres-row-retention',
      passed: sameRows,
      ...(!sameRows
        ? { cause: 'Legacy PostgreSQL row identities changed' }
        : {}),
    },
    {
      id: 'no-rewrite.postgres-retained-bytes',
      passed: changed.length === 0,
      ...(changed.length
        ? { cause: `Changed PostgreSQL attributes: ${changed.join(', ')}` }
        : {}),
    },
    {
      id: 'migration.postgres-v3-columns',
      passed: mapped,
      ...(!mapped
        ? {
            cause:
              'Expected source columns and v3 target mappings are missing or incorrect',
          }
        : {}),
    },
    {
      id: 'migration.postgres-indexes',
      passed: indexed,
      ...(!indexed
        ? { cause: 'Required valid, complete equality indexes are missing' }
        : {}),
    },
  ]
}
