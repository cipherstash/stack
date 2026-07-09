import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { QueryTypeName } from '@/types'
import type {
  DbFilterString,
  DbPendingOrCondition,
  DbSelect,
  FilterOp,
  PendingOrCondition,
} from './types'

/**
 * Get the names of all encrypted columns defined in a table schema.
 */
export function getEncryptedColumnNames(
  schema: EncryptedTable<EncryptedTableColumn>,
): string[] {
  const built = schema.build()
  return Object.keys(built.columns)
}

/**
 * Check whether a column name refers to an encrypted column in the schema.
 */
export function isEncryptedColumn(
  columnName: string,
  encryptedColumnNames: string[],
): boolean {
  return encryptedColumnNames.includes(columnName)
}

/**
 * Parse a Supabase select string and add `::jsonb` casts to encrypted columns.
 *
 * Input:  `'id, email, name'`
 * Output: `'id, email::jsonb, name::jsonb'`  (if email and name are encrypted)
 *
 * Handles whitespace, already-cast columns, and embedded functions.
 */
export function addJsonbCasts(
  columns: string,
  encryptedColumnNames: string[],
): DbSelect {
  // The mapping below emits DB-space tokens; the brand is asserted once, here.
  return columns
    .split(',')
    .map((col) => {
      const trimmed = col.trim()

      // Skip empty segments
      if (!trimmed) return col

      // If it already has a cast (e.g. `email::jsonb`), skip
      if (trimmed.includes('::')) return col

      // If it contains parens (function call) or dots (foreign table), skip
      if (trimmed.includes('(') || trimmed.includes('.')) return col

      // Check if the column name (possibly with alias) is encrypted
      // Handle `column_name` or `column_name as alias`
      const parts = trimmed.split(/\s+/)
      const colName = parts[0]

      if (isEncryptedColumn(colName, encryptedColumnNames)) {
        // Preserve original whitespace before the column
        const leadingWhitespace = col.match(/^(\s*)/)?.[1] ?? ''
        if (parts.length > 1) {
          // Has alias: `email as e` -> `email::jsonb as e`
          return `${leadingWhitespace}${colName}::jsonb ${parts.slice(1).join(' ')}`
        }
        return `${leadingWhitespace}${colName}::jsonb`
      }

      return col
    })
    .join(',') as DbSelect
}

/**
 * Resolve a select token to its DB column name, or `undefined`.
 *
 * `Object.hasOwn` is required, not decorative: the token comes from the caller's
 * select string (or, for `select('*')`, from the database's own column list).
 * `buildColumnKeyMap()` already returns a null-prototype map, but an inherited
 * `Object.prototype` member is truthy, so a plain-object map would let a column
 * named `constructor` interpolate `function Object() { … }` into the emitted
 * select string. Both guards are kept — a future refactor that drops the null
 * prototype must not silently reopen the hole.
 */
function lookupDbName(
  propToDb: Record<string, string>,
  token: string,
): string | undefined {
  return Object.hasOwn(propToDb, token) ? propToDb[token] : undefined
}

/**
 * Parse a Supabase select string and add `::jsonb` casts to encrypted EQL v3
 * columns, resolving JS property names to DB column names via PostgREST
 * aliasing.
 *
 * Input:  `'id, email, createdAt'` with `{ email: 'email', createdAt: 'created_at' }`
 * Output: `'id, email::jsonb, createdAt:created_at::jsonb'`
 *
 * - A property whose DB name differs is emitted as `prop:db_name::jsonb`
 *   (PostgREST rename syntax), so result rows come back keyed by the JS
 *   property name.
 * - A DB column name used directly is cast in place (`db_name::jsonb`).
 * - Tokens that already carry a cast, or contain parens/dots (functions,
 *   foreign tables), are left untouched — same rules as the v2 helper.
 */
export function addJsonbCastsV3(
  columns: string,
  propToDb: Record<string, string>,
): DbSelect {
  const dbNames = new Set(Object.values(propToDb))

  return columns
    .split(',')
    .map((col) => {
      const trimmed = col.trim()

      if (!trimmed) return col
      if (trimmed.includes('::')) return col
      if (trimmed.includes('(') || trimmed.includes('.')) return col

      const leadingWhitespace = col.match(/^(\s*)/)?.[1] ?? ''

      // Already-aliased token: `alias:column`
      const aliasMatch = trimmed.match(
        /^([A-Za-z_][A-Za-z0-9_]*):([A-Za-z_][A-Za-z0-9_]*)$/,
      )
      if (aliasMatch) {
        const [, alias, name] = aliasMatch
        const db =
          lookupDbName(propToDb, name) ?? (dbNames.has(name) ? name : undefined)
        if (db !== undefined) {
          return `${leadingWhitespace}${alias}:${db}::jsonb`
        }
        return col
      }

      const db = lookupDbName(propToDb, trimmed)
      if (db !== undefined) {
        return db === trimmed
          ? `${leadingWhitespace}${trimmed}::jsonb`
          : `${leadingWhitespace}${trimmed}:${db}::jsonb`
      }

      if (dbNames.has(trimmed)) {
        return `${leadingWhitespace}${trimmed}::jsonb`
      }

      return col
    })
    .join(',') as DbSelect
}

/**
 * Whether a filter operand is a value to be encrypted and compared, rather than
 * a SQL predicate. Every term collector must consult this before pushing an
 * encryption term.
 *
 * - `is` is a predicate, not a comparison: PostgREST accepts only
 *   `null`/`true`/`false`/`unknown` after it, so an encrypted operand is
 *   rejected. The operand is non-null for `is(col, false)`, so the operator
 *   must be checked independently of the value.
 * - A `null`/`undefined` operand is SQL NULL. A null plaintext is stored as a
 *   NULL column, not as ciphertext, so it is found with an unencrypted
 *   `IS NULL` — encrypting the operand can never match anything.
 *
 * `operator` is widened to `string` because raw `filter()` accepts any
 * PostgREST operator, not just a {@link FilterOp}.
 */
export function isEncryptableTerm(
  operator: FilterOp | string,
  value: unknown,
): boolean {
  if (operator === 'is') return false
  return value != null
}

/**
 * Map a Supabase filter operation to a CipherStash query type.
 */
export function mapFilterOpToQueryType(op: FilterOp): QueryTypeName {
  switch (op) {
    case 'eq':
    case 'neq':
    case 'in':
    case 'is':
      return 'equality'
    case 'like':
    case 'ilike':
    case 'contains':
      return 'freeTextSearch'
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      return 'orderAndRange'
    default:
      return 'equality'
  }
}

/**
 * Parse a Supabase `.or()` filter string into structured conditions.
 *
 * Input: `'email.eq.john@example.com,name.ilike.%john%'`
 * Output: `[{ column: 'email', op: 'eq', negate: false, value: 'john@example.com' }, …]`
 *
 * PostgREST spells negation `column.not.<op>.<value>`. It is lifted onto its own
 * `negate` flag rather than left as the operator: the term collector keys the
 * `in`-list split on `op === 'in'`, so a negated list parsed as
 * `{ op: 'not', value: 'in.(a,b)' }` skipped the split and encrypted the literal
 * string `in.(a,b)` as a single plaintext — a filter that silently matched
 * nothing. Only a `not` in the OPERATOR position is a prefix; a column or value
 * of that name is untouched.
 */
export function parseOrString(orString: string): PendingOrCondition[] {
  const conditions: PendingOrCondition[] = []
  // Split on commas that are not inside parentheses (nested or/and)
  const parts = splitOrString(orString)

  for (const part of parts) {
    const trimmed = part.trim()
    if (!trimmed) continue

    // Format: column.op.value — or column.not.op.value
    const firstDot = trimmed.indexOf('.')
    if (firstDot === -1) continue

    const column = trimmed.slice(0, firstDot)
    let rest = trimmed.slice(firstDot + 1)

    let negate = false
    if (rest.startsWith('not.')) {
      const afterNot = rest.slice('not.'.length)
      // `col.not.<op>.<value>` needs an operator AND a value after the prefix.
      // Without the second dot, `not` IS the operator (or the string is
      // malformed) — leave it alone rather than swallow the operator.
      if (afterNot.includes('.')) {
        negate = true
        rest = afterNot
      }
    }

    const secondDot = rest.indexOf('.')
    if (secondDot === -1) continue

    const op = rest.slice(0, secondDot) as FilterOp
    const value = rest.slice(secondDot + 1)

    // Handle special value formats
    const parsedValue = parseOrValue(value)

    conditions.push({ column, op, negate, value: parsedValue })
  }

  return conditions
}

/**
 * PostgREST operator tokens whose operand is a CONTAINMENT literal — a
 * Postgres array literal (`{vip,admin}`) or a jsonb literal (`{"a":1}`) — rather
 * than a scalar or the `in`-list's `(a,b)`.
 *
 * `contains` is supabase-js's METHOD name for this operator; string-form `.or()`
 * callers write PostgREST's `cs` directly. Both reach here.
 */
const CONTAINMENT_OPS = new Set(['contains', 'cs'])

/**
 * The PostgREST operator token for a {@link FilterOp}.
 *
 * `contains` is the only member of the union that is a supabase-js method name
 * rather than a PostgREST operator: `eq`, `in`, `like`, `is` and the rest spell
 * the same on both sides, but PostgREST's containment operator is `cs`, and
 * `or=(tags.contains.vip)` is a PGRST100 parse error ("unexpected \"c\"
 * expecting \"not\" or operator").
 *
 * Applied unconditionally, NOT only to encrypted conditions. The token depends
 * on the operator, never on whether the operand was encrypted — a plaintext
 * jsonb/array column reached through `.or([{op: 'contains'}])` needs exactly the
 * same translation, and gating it on encryption is what left plaintext
 * containment broken while the encrypted path worked.
 */
function orOperatorToken(op: string): string {
  return op === 'contains' ? 'cs' : op
}

/**
 * Rebuild an `.or()` string from structured conditions.
 */
export function rebuildOrString(
  conditions: DbPendingOrCondition[],
): DbFilterString {
  // Callers must hand DB-space `c.column` values (see `toDbSpace`).
  return conditions
    .map((c) => {
      const op = orOperatorToken(c.op)
      const value = formatOrValue(c.value, op)
      const token = c.negate ? `not.${op}` : op
      return `${c.column}.${token}.${value}`
    })
    .join(',') as DbFilterString
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function splitOrString(input: string): string[] {
  const parts: string[] = []
  let current = ''
  let depth = 0
  let inQuotes = false

  let escaped = false

  for (const char of input) {
    // A backslash-escaped character is literal: `\"` must NOT toggle `inQuotes`,
    // or an escaped quote inside an encrypted operand would end the token and
    // the next comma would split mid-value.
    if (escaped) {
      escaped = false
      current += char
    } else if (char === '\\' && inQuotes) {
      escaped = true
      current += char
    } else if (char === '"' && depth === 0) {
      inQuotes = !inQuotes
      current += char
    } else if ((char === '(' || char === '{') && !inQuotes) {
      // `{` as well as `(`: a containment operand is an array (`{vip,admin}`) or
      // a jsonb (`{"a":1,"b":2}`) literal, whose top-level commas are part of
      // the value. PostgREST's own logic-tree parser tracks these braces;
      // without them a condition splits mid-literal into `tags.cs.{vip` and a
      // dotless fragment `admin}` that the loop below silently drops.
      depth++
      current += char
    } else if ((char === ')' || char === '}') && !inQuotes) {
      depth--
      current += char
    } else if (char === ',' && depth === 0 && !inQuotes) {
      parts.push(current)
      current = ''
    } else {
      current += char
    }
  }

  if (current) {
    parts.push(current)
  }

  return parts
}

function parseOrValue(value: string): unknown {
  // Handle double-quoted values (PostgREST quoting for reserved characters).
  // Must undo `escapeOrValue`, or a parse → rebuild round-trip doubles every
  // backslash. The two functions are only correct as a pair.
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return unescapeOrValue(value.slice(1, -1))
  }

  // Handle parenthesized lists: (val1,val2,val3)
  if (value.startsWith('(') && value.endsWith(')')) {
    return value
      .slice(1, -1)
      .split(',')
      .map((v) => v.trim())
  }

  // Handle booleans
  if (value === 'true') return true
  if (value === 'false') return false

  // Handle null
  if (value === 'null') return null

  return value
}

/**
 * PostgREST characters that require double-quoting in filter values.
 *
 * `"` and `\` are here because a value containing either must be quoted AND
 * escaped: unquoted, a bare `"` is a syntax error mid-value; quoted but
 * unescaped, it terminates the value early. Every v3 encrypted operand is
 * `JSON.stringify(envelope)`, so this is the common case, not the exotic one.
 *
 * See: https://docs.postgrest.org/en/latest/references/api/tables_views.html
 */
const POSTGREST_RESERVED = /["\\,().]/

/** Escape `\` first, then `"` — the reverse order would double-escape. */
function escapeOrValue(str: string): string {
  return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** Inverse of {@link escapeOrValue}: consume `\x` as a literal `x`. */
function unescapeOrValue(str: string): string {
  return str.replace(/\\(.)/g, '$1')
}

/**
 * Characters that force an ARRAY-literal element to be double-quoted. Wider
 * than {@link POSTGREST_RESERVED} because the braces and whitespace that are
 * harmless in a scalar operand are structural inside `{…}`.
 */
const ARRAY_ELEMENT_RESERVED = /[,"\\{}()\s]/

/** One element of a Postgres array literal. `NULL` is a keyword there, so a
 * string that happens to spell it must be quoted to stay a string. */
function arrayLiteralElement(value: unknown): string {
  if (value === null || value === undefined) return 'NULL'
  const str = String(value)
  if (str === '' || ARRAY_ELEMENT_RESERVED.test(str) || /^null$/i.test(str)) {
    return `"${escapeOrValue(str)}"`
  }
  return str
}

/**
 * The `cs` operand for a structured value: `{a,b}` for an array column,
 * `{"a":1}` for a jsonb one. Returns null when `value` is a scalar, which takes
 * the ordinary path — notably the v3 encrypted operand, already a
 * `JSON.stringify`d envelope STRING, which must not be re-serialized.
 */
function containmentLiteral(value: unknown): string | null {
  if (Array.isArray(value)) {
    return `{${value.map((v) => arrayLiteralElement(v)).join(',')}}`
  }
  if (value !== null && typeof value === 'object' && !(value instanceof Date)) {
    return JSON.stringify(value)
  }
  return null
}

function formatOrValue(value: unknown, op?: string): string {
  // A containment literal is a VALUE like any other once built: it goes on to
  // the quoting below, because its comma would otherwise split the or-string at
  // the top level. PostgREST accepts a quoted `"{vip,admin}"` inside `or=(…)`.
  if (op !== undefined && CONTAINMENT_OPS.has(op)) {
    const literal = containmentLiteral(value)
    if (literal !== null) return formatOrValue(literal)
  }

  if (Array.isArray(value)) {
    return `(${value.map((v) => formatOrValue(v)).join(',')})`
  }
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'

  const str = String(value)

  // Wrap in double quotes if the value contains reserved characters.
  // This is required for encrypted values (JSON with commas, braces, etc.)
  // and is safe for all string values per PostgREST spec.
  if (POSTGREST_RESERVED.test(str)) {
    return `"${escapeOrValue(str)}"`
  }

  return str
}

/**
 * The operand for an `in`/`not.in` list: `(a,b)`, each element quoted and
 * escaped exactly as the `or` path does.
 *
 * Required because postgrest-js's own `in()` wraps a comma-bearing element in
 * `"…"` but never escapes the `"` already inside it — and every v3 encrypted
 * operand is a `JSON.stringify`d envelope, so its quotes would terminate the
 * value early. Emit this through `filter(col, 'in', …)` / `not(col, 'in', …)`,
 * both of which forward the operand verbatim.
 */
export function formatInListOperand(values: readonly unknown[]): string {
  return formatOrValue([...values])
}
