import { isDeepStrictEqual } from 'node:util'

/** Compare stored bytes through admin snapshots, without exporting their values.
 * @param {unknown} before @param {unknown} after
 * @returns {import('../types.js').OracleCheck} */
export function noRewrite(before, after) {
  /** @param {unknown} snapshot */
  function fields(snapshot, baseline = false) {
    /** @type {Map<string, unknown>} */
    const result = new Map()
    if (!snapshot || typeof snapshot !== 'object')
      throw Error('Invalid Legacy Data snapshot')
    const data = Object.fromEntries(Object.entries(snapshot))
    const item = data.dynamo?.Item
    if (!Array.isArray(data.postgres))
      throw Error('Missing Legacy Data snapshot')
    for (const [key, value] of Object.entries(item ?? {}))
      if (/__(source|hmac)$/.test(key))
        result.set(`dynamo/${item.pk.S}/${key}`, value)
    for (const row of data.postgres)
      for (const [column, payload] of Object.entries(row)) {
        if (column === 'pk' || !payload || typeof payload !== 'object') continue
        for (const attribute of ['c', 'hm'])
          if (attribute in payload)
            result.set(
              `postgres/${row.pk}/${column}.${attribute}`,
              Object.fromEntries(Object.entries(payload))[attribute],
            )
      }
    if (baseline && !result.size)
      throw Error('Legacy Data snapshot contains no encrypted attributes')
    return result
  }
  const expected = fields(before, true)
  const actual = fields(after)
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
