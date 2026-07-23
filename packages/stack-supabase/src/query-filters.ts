import type { ColumnMap } from './column-map'
import {
  formatContainmentOperand,
  formatInListOperand,
  isEncryptedColumn,
  rebuildOrString,
} from './helpers'
import {
  assertPostgrestCanQueryEncryptedOperator,
  type EncryptedFilterState,
} from './query-encrypt'
import type {
  DbFilterString,
  DbName,
  DbQuerySpace,
  FilterOp,
  SupabaseQueryBuilder,
} from './types'

/** Key an `.or()` condition, or one element of its `in` list. */
function orKey(mapping: {
  orIndex: number
  conditionIndex: number
  inIndex?: number
}): string {
  const base = `${mapping.orIndex}:${mapping.conditionIndex}`
  return mapping.inIndex === undefined ? base : `${base}:${mapping.inIndex}`
}

/**
 * Substitute encrypted operands back into one `.or()` condition, returning
 * `undefined` when nothing was encrypted for it.
 *
 * An `in` list is reconstructed element-by-element so `formatOrValue` re-emits
 * the `(a,b)` list form. Substituting the array as a single value would collapse
 * it to one ciphertext that matches nothing.
 */
function substituteOrValue(
  map: Map<string, unknown>,
  orIndex: number,
  conditionIndex: number,
  cond: { op: FilterOp; value: unknown },
): { value: unknown } | undefined {
  const whole = orKey({ orIndex, conditionIndex })
  if (map.has(whole)) return { value: map.get(whole) }

  if (cond.op === 'in' && Array.isArray(cond.value)) {
    let substituted = false
    const value = cond.value.map((element, inIndex) => {
      const key = orKey({ orIndex, conditionIndex, inIndex })
      if (!map.has(key)) return element
      substituted = true
      return map.get(key)
    })
    if (substituted) return { value }
  }

  return undefined
}

/**
 * Apply an `in` filter.
 *
 * A plaintext list goes to postgrest-js's `in()`, which quotes elements that
 * contain `,()`. An ENCRYPTED list cannot: every element is a
 * `JSON.stringify`d envelope, and `in()` wraps it in `"…"` without escaping
 * the quotes inside it, so PostgREST terminates the value at the envelope's
 * first `"`. Emit the operand ourselves and hand it to `filter()`, which
 * forwards it verbatim.
 */
function applyInFilter(
  q: SupabaseQueryBuilder,
  column: DbName,
  values: unknown[],
  wasEncrypted: boolean,
): SupabaseQueryBuilder {
  if (!wasEncrypted) return q.in(column, values)
  return q.filter(column, 'in', formatInListOperand(values))
}

/**
 * Apply a `like`/`ilike` filter. On an encrypted column `like`/`ilike` were
 * rewritten to `matches` at record time, so a `like`/`ilike` pending filter
 * only ever names a plaintext column, which keeps real SQL LIKE.
 */
function applyPatternFilter(
  q: SupabaseQueryBuilder,
  column: DbName,
  op: 'like' | 'ilike',
  value: unknown,
): SupabaseQueryBuilder {
  return op === 'like'
    ? q.like(column, value as string)
    : q.ilike(column, value as string)
}

/**
 * Apply a `contains` filter. On a plaintext column this is PostgREST's native
 * jsonb/array containment. On an encrypted column `cs` resolves to the `@>`
 * operator the EQL bundle declares on the domain, backed by `eql_v3.matches`
 * (bloom-filter containment) — and the operand is the full storage envelope,
 * already `JSON.stringify`d, emitted via `filter(col, 'cs', json)` rather than
 * `q.contains` (postgrest-js's `contains` re-serializes a non-string operand).
 *
 * A structured plaintext operand is serialized here rather than by
 * postgrest-js, which joins array elements on `,` without quoting them — so
 * `['with,comma']` would reach Postgres as two elements. Scalars keep the
 * native path.
 */
function applyContainsFilter(
  q: SupabaseQueryBuilder,
  column: DbName,
  value: unknown,
  wasEncrypted: boolean,
  queryDomainsRequired: boolean,
): SupabaseQueryBuilder {
  if (wasEncrypted) {
    assertPostgrestCanQueryEncryptedOperator(
      queryDomainsRequired,
      'filter',
      column,
    )
    return q.filter(column, 'cs', value)
  }
  const literal = formatContainmentOperand(value)
  return literal !== null
    ? q.filter(column, 'cs', literal)
    : q.contains(column, value)
}

/**
 * Apply every recorded filter to the real Supabase query, substituting the
 * encrypted operand wherever one was produced for that position.
 */
export function applyFilters(
  query: SupabaseQueryBuilder,
  encryptedFilters: EncryptedFilterState,
  dbSpace: DbQuerySpace,
  columns: ColumnMap,
  queryDomainsRequired: boolean,
): SupabaseQueryBuilder {
  let q = query
  const encryptedColumnNames = columns.encryptedColumnNames

  // Build lookup maps for quick access to encrypted values
  const filterValueMap = new Map<number, unknown>()
  const filterInMap = new Map<string, unknown>() // "filterIndex:inIndex" -> value
  const matchValueMap = new Map<string, unknown>() // "matchIndex:column" -> value
  const notValueMap = new Map<number, unknown>()
  const notInMap = new Map<string, unknown>() // "notIndex:inIndex" -> value
  const rawValueMap = new Map<number, unknown>()
  const rawInMap = new Map<string, unknown>() // "rawIndex:inIndex" -> value
  const orStringConditionMap = new Map<string, unknown>() // "orIndex:condIndex" -> value
  const orStructuredConditionMap = new Map<string, unknown>()

  for (let i = 0; i < encryptedFilters.termMap.length; i++) {
    const mapping = encryptedFilters.termMap[i]
    const encValue = encryptedFilters.encryptedValues[i]

    switch (mapping.source) {
      case 'filter':
        if (mapping.inIndex !== undefined) {
          filterInMap.set(`${mapping.filterIndex}:${mapping.inIndex}`, encValue)
        } else {
          filterValueMap.set(mapping.filterIndex, encValue)
        }
        break
      case 'match':
        matchValueMap.set(`${mapping.matchIndex}:${mapping.column}`, encValue)
        break
      case 'not':
        if (mapping.inIndex !== undefined) {
          notInMap.set(`${mapping.notIndex}:${mapping.inIndex}`, encValue)
        } else {
          notValueMap.set(mapping.notIndex, encValue)
        }
        break
      case 'raw':
        if (mapping.inIndex !== undefined) {
          rawInMap.set(`${mapping.rawIndex}:${mapping.inIndex}`, encValue)
        } else {
          rawValueMap.set(mapping.rawIndex, encValue)
        }
        break
      // `inIndex` widens the key to address one element of an `in` list, so a
      // whole-condition value and a per-element value never collide.
      case 'or-string':
        orStringConditionMap.set(orKey(mapping), encValue)
        break
      case 'or-structured':
        orStructuredConditionMap.set(orKey(mapping), encValue)
        break
    }
  }

  // Apply regular filters
  for (let i = 0; i < dbSpace.filters.length; i++) {
    const f = dbSpace.filters[i]
    let value = f.value

    if (filterValueMap.has(i)) {
      value = filterValueMap.get(i)
    } else if (f.op === 'in' && Array.isArray(f.value)) {
      // Reconstruct array with encrypted values substituted
      value = f.value.map((v, j) => {
        const key = `${i}:${j}`
        return filterInMap.has(key) ? filterInMap.get(key) : v
      })
    }

    const column = f.column
    const wasEncrypted = filterValueMap.has(i)

    switch (f.op) {
      case 'eq':
        q = q.eq(column, value)
        break
      case 'neq':
        q = q.neq(column, value)
        break
      case 'gt':
        q = q.gt(column, value)
        break
      case 'gte':
        q = q.gte(column, value)
        break
      case 'lt':
        q = q.lt(column, value)
        break
      case 'lte':
        q = q.lte(column, value)
        break
      case 'like':
      case 'ilike':
        q = applyPatternFilter(q, column, f.op, value)
        break
      // `matches` (encrypted free-text) and `contains` (plaintext / encrypted
      // JSON) share the `cs`/`@>` wire operator; the operand encoding is the
      // same, so both emit through the one containment applier.
      case 'contains':
      case 'matches':
        q = applyContainsFilter(
          q,
          column,
          value,
          wasEncrypted,
          queryDomainsRequired,
        )
        break
      case 'is':
        q = q.is(column, value)
        break
      case 'in':
        // `wasEncrypted` above is false for in-lists: their ciphertexts land
        // in `filterInMap`, keyed per element.
        q = applyInFilter(
          q,
          column,
          value as unknown[],
          Array.isArray(f.value) &&
            f.value.some((_, j) => filterInMap.has(`${i}:${j}`)),
        )
        break
    }
  }

  // Apply match filters
  for (let i = 0; i < dbSpace.matchFilters.length; i++) {
    const mf = dbSpace.matchFilters[i]
    const resolvedQuery: Record<string, unknown> = {}

    for (const { column: colName, value: originalValue } of mf.entries) {
      const key = `${i}:${colName}`
      resolvedQuery[colName] = matchValueMap.has(key)
        ? matchValueMap.get(key)
        : originalValue
    }

    q = q.match(resolvedQuery)
  }

  // Apply not filters
  for (let i = 0; i < dbSpace.notFilters.length; i++) {
    const nf = dbSpace.notFilters[i]

    if (nf.op === 'in' && Array.isArray(nf.value)) {
      const values = nf.value.map((v, j) =>
        notInMap.has(`${i}:${j}`) ? notInMap.get(`${i}:${j}`) : v,
      )
      q = q.not(nf.column, 'in', formatInListOperand(values))
      continue
    }

    const wasEncrypted = notValueMap.has(i)
    const value = wasEncrypted ? notValueMap.get(i) : nf.value

    // `contains` is a supabase-js METHOD name, not a PostgREST operator, and
    // `q.not()` interpolates its operand with `String(value)` — so an array
    // arrives brace-less and an object as `[object Object]`. Build the
    // containment literal ourselves and emit the `cs` token, exactly as the
    // `.or()` path does. A scalar (including the encrypted envelope, already
    // serialized) yields `null` and is forwarded untouched.
    if (nf.op === 'contains' || nf.op === 'matches') {
      const literal = formatContainmentOperand(value)
      q = q.not(nf.column, 'cs', literal ?? value)
      continue
    }

    // Every `FilterOp` except `contains` spells the same as its PostgREST
    // operator, and `contains` was handled above (it also needs its operand
    // rewritten), so the recorded op is the wire op.
    q = q.not(nf.column, nf.op, value)
  }

  // Apply or filters
  for (let i = 0; i < dbSpace.orFilters.length; i++) {
    const of_ = dbSpace.orFilters[i]

    if (of_.kind === 'string') {
      // Already parsed (once) and translated by `toDbSpace`.
      const parsed = [...of_.conditions]

      for (let j = 0; j < parsed.length; j++) {
        const sub = substituteOrValue(orStringConditionMap, i, j, parsed[j])
        if (sub) {
          parsed[j] = { ...parsed[j], value: sub.value }
        }
      }

      // Rebuild whenever a condition REFERENCES an encrypted column — not
      // merely when a value was encrypted. An `is`/null operand on an
      // encrypted column encrypts nothing, so keying on "was a value
      // substituted" would send that condition down the verbatim path below
      // and forward the caller's JS property name to a DB that only knows the
      // column's real name. `toDbSpace` has already translated `parsed`.
      const referencesEncrypted = parsed.some((c) =>
        isEncryptedColumn(c.column, encryptedColumnNames),
      )

      if (referencesEncrypted) {
        q = q.or(rebuildOrString(parsed), {
          referencedTable: of_.referencedTable,
        })
      } else {
        // Every condition names a plaintext column, whose property name IS
        // its DB name — nothing to map. Forward the caller's ORIGINAL string
        // byte-for-byte: relied on for nested `and()` and quoted values that
        // `parseOrString`/`rebuildOrString` cannot round-trip.
        q = q.or(of_.original as DbFilterString, {
          referencedTable: of_.referencedTable,
        })
      }
    } else {
      // Structured: convert to string
      const conditions = of_.conditions.map((cond, j) => {
        const sub = substituteOrValue(orStructuredConditionMap, i, j, cond)
        return sub ? { ...cond, value: sub.value } : cond
      })

      q = q.or(rebuildOrString(conditions))
    }
  }

  // Apply raw filters
  for (let i = 0; i < dbSpace.rawFilters.length; i++) {
    const rf = dbSpace.rawFilters[i]

    // An encrypted `in` list was encrypted element-wise; reassemble it into
    // the quoted PostgREST list literal, exactly as the `not` path does. A
    // plaintext column keeps its operand untouched.
    if (
      rf.operator === 'in' &&
      Array.isArray(rf.value) &&
      isEncryptedColumn(rf.column, encryptedColumnNames)
    ) {
      const values = rf.value.map((v, j) =>
        rawInMap.has(`${i}:${j}`) ? rawInMap.get(`${i}:${j}`) : v,
      )
      q = q.filter(rf.column, rf.operator, formatInListOperand(values))
      continue
    }

    const value = rawValueMap.has(i) ? rawValueMap.get(i) : rf.value
    q = q.filter(rf.column, rf.operator, value)
  }

  return q
}
