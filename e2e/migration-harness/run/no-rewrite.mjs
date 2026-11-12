import { isDeepStrictEqual } from 'node:util'
import { dynamoColumns, hasHmac, postgresColumns } from './legacy-columns.mjs'
import { object } from './record.mjs'

/** Compare stored bytes through admin snapshots, without exporting their values.
 * @param {unknown} before @param {unknown} after
 * @returns {import('../types.js').OracleCheck} */
export function noRewrite(before, after) {
  /** @param {unknown} snapshot */
  function fields(snapshot, baseline = false) {
    /** @type {Map<string, unknown>} */
    const result = new Map()
    const data = object(snapshot)
    const item = object(object(data.dynamo ?? {}).Item ?? {})
    if (!Array.isArray(data.postgres) || data.postgres.length !== 1)
      throw Error('Expected exactly one Legacy Data Postgres row')
    for (const [key, value] of Object.entries(item))
      if (/__(source|hmac)$/.test(key))
        result.set(
          `dynamo/${object(item.pk ?? {}).S ?? 'legacy'}/${key}`,
          value,
        )
    for (const raw of data.postgres) {
      const row = object(raw)
      for (const [column, payload] of Object.entries(row)) {
        if (column === 'pk' || !payload || typeof payload !== 'object') continue
        const attributes = object(payload)
        for (const attribute of ['c', 'hm'])
          if (attribute in attributes)
            result.set(
              `postgres/${row.pk}/${column}.${attribute}`,
              attributes[attribute],
            )
      }
    }
    if (baseline && !result.size)
      throw Error('Legacy Data snapshot contains no encrypted attributes')
    return result
  }
  // A malformed baseline is infrastructure; a malformed current snapshot is
  // app damage, so it fails this check rather than hiding it from the report.
  const expected = fields(before, true)
  /** @type {Map<string, unknown>} */
  let actual
  try {
    actual = fields(after)
  } catch {
    return {
      id: 'no-rewrite.legacy-bytes',
      passed: false,
      cause: 'Current Legacy Data snapshot does not match the baseline shape',
    }
  }
  const changed = [...new Set([...expected.keys(), ...actual.keys()])].filter(
    (key) =>
      !expected.has(key) ||
      !actual.has(key) ||
      !isDeepStrictEqual(expected.get(key), actual.get(key)),
  )
  return {
    id: 'no-rewrite.legacy-bytes',
    passed: changed.length === 0,
    ...(changed.length
      ? { cause: `Changed Legacy Data attributes: ${changed.join(', ')}` }
      : {}),
  }
}

/** Validate the known Fixture App baseline before any Migrator invocation.
 * @param {unknown} snapshot */
export function validateLegacySnapshot(snapshot) {
  const data = object(snapshot)
  const item = object(object(data.dynamo).Item)
  if (!Array.isArray(data.postgres) || data.postgres.length !== 1)
    throw Error('Expected exactly one Legacy Data Postgres row')
  const row = object(data.postgres[0])
  if (object(item.pk).S !== 'legacy' || row.pk !== 'legacy')
    throw Error('Missing Legacy Data record')
  for (const column of dynamoColumns) {
    if (
      typeof object(item[`${column}__source`] ?? {}).S !== 'string' ||
      (hasHmac(column) &&
        typeof object(item[`${column}__hmac`] ?? {}).S !== 'string')
    )
      throw Error(`Incomplete Legacy Data DynamoDB column: ${column}`)
  }
  for (const column of postgresColumns) {
    const attributes = object(row[column] ?? {})
    if (
      typeof attributes.c !== 'string' ||
      (hasHmac(column) && typeof attributes.hm !== 'string')
    )
      throw Error(`Incomplete Legacy Data Postgres column: ${column}`)
  }
}
