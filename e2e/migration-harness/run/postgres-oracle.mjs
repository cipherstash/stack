import { isDeepStrictEqual } from 'node:util'
import { object } from './record.mjs'

const columns = ['email', 'age', 'notes']
const targetTypes = ['eql_v3_text_eq', 'eql_v3_integer_eq', 'eql_v3_text']
export const requiredPostgresChecks = [
  'behaviour.postgres-row-retention',
  'no-rewrite.postgres-retained-bytes',
  'migration.postgres-v3-columns',
  'migration.postgres-indexes',
  'behaviour.postgres-legacy-read',
  'behaviour.postgres-email-lookup',
  'behaviour.postgres-age-lookup',
  'behaviour.postgres-fresh-write',
  'behaviour.postgres-fresh-lookups',
  'migration.postgres-fresh-v3-storage',
  'migration.protect-dependencies-absent',
  'migration.protect-ffi-version',
  'migration.endpoint-shim-absent',
]

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
        Object.keys(payload).some(
          (key) => !['v', 'k', 'i', 'c', 'hm', 'ob', 'bf'].includes(key),
        ) ||
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
  return data
}

/** Compare only bytes proven retained by the guide. Version and envelope fields
 * legitimately change; source columns, ciphertext and equality terms must remain.
 * Snapshotting runs with the harness's admin connection, never inside App Host.
 * @param {unknown} before @param {unknown} after
 * @returns {import('../types.js').OracleCheck[]} */
export function postgresMigrationChecks(before, after) {
  const baseline = validatePostgresBaseline(before)
  let current
  try {
    current = read(after)
  } catch {
    return requiredPostgresChecks.slice(0, 4).map((id) => ({
      id,
      passed: false,
      cause: 'Invalid migrated PostgreSQL snapshot identities or structure',
    }))
  }
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
      if (!isDeepStrictEqual(actual?.[column], source))
        changed.push(`${pk}/${column}`)
      const value = migratedPayload(actual?.[`${column}_v3`])
      if (value.c !== source.c || (value.hm ?? null) !== (source.hm ?? null))
        changed.push(`${pk}/${column}_v3`)
      const target = migratedPayload(actual?.[`${column}_v3`])
      if (
        !validTarget(target, column) ||
        !isDeepStrictEqual(target.i, source.i)
      )
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

/** @param {Record<string, unknown>} target @param {string} column */
function validTarget(target, column) {
  const keys = column === 'notes' ? ['v', 'i', 'c'] : ['v', 'i', 'c', 'hm']
  return (
    isDeepStrictEqual(Object.keys(target).sort(), keys.sort()) &&
    target.v === 3 &&
    typeof target.c === 'string' &&
    target.c.length > 0 &&
    isDeepStrictEqual(target.i, { t: 'customers', c: column }) &&
    (column === 'notes' ||
      (typeof target.hm === 'string' && target.hm.length > 0))
  )
}

/** Inspect fresh storage independently of application return values.
 * @param {unknown} snapshot @param {string} pk
 * @returns {import('../types.js').OracleCheck} */
export function postgresFreshWriteCheck(snapshot, pk) {
  let passed = false
  try {
    const row = read(snapshot).rows.get(pk)
    passed =
      !!row &&
      columns.every(
        (column) =>
          row[column] === null &&
          validTarget(migratedPayload(row[`${column}_v3`]), column),
      )
  } catch {
    /* Invalid stored evidence is a failed check. */
  }
  return {
    id: 'migration.postgres-fresh-v3-storage',
    passed,
    ...(!passed
      ? {
          cause:
            'Fresh PostgreSQL row must use v3 targets and leave retained source columns null',
        }
      : {}),
  }
}
