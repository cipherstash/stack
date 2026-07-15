import type {
  EncryptedTable,
  EncryptedTableColumn,
} from '@cipherstash/stack/schema'
import type { QueryTypeName } from '@cipherstash/stack/types'
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
      const resolved = resolveSelectToken(col.trim(), propToDb, dbNames)
      if (resolved === null) return col

      const leadingWhitespace = col.match(/^(\s*)/)?.[1] ?? ''
      return `${leadingWhitespace}${resolved.emit}`
    })
    .join(',') as DbSelect
}

/**
 * The result-row key each encrypted column comes back under for a given select
 * string, mapped to its DB column name.
 *
 * The two differ whenever PostgREST renames: `createdAt` on a `created_at`
 * column keys rows by `createdAt`, and a caller-chosen alias (`ts:createdAt`)
 * keys them by `ts`. Consumers that resolve per-column config by DB name —
 * `postprocessDecryptedRow` reading `cast_as` to rebuild `Date` values — need
 * this bridge, because the row key alone does not identify the column.
 *
 * Shares {@link resolveSelectToken} with {@link addJsonbCastsV3} so the keys
 * this reports are exactly the keys that helper causes PostgREST to emit. Any
 * token the cast helper leaves untouched is absent here.
 */
export function selectKeyToDbV3(
  columns: string,
  propToDb: Record<string, string>,
): Record<string, string> {
  const dbNames = new Set(Object.values(propToDb))
  const keyToDb: Record<string, string> = Object.create(null)

  for (const col of columns.split(',')) {
    const resolved = resolveSelectToken(col.trim(), propToDb, dbNames)
    if (resolved !== null) keyToDb[resolved.key] = resolved.db
  }

  return keyToDb
}

/**
 * Resolve one select-string token to the row key it produces, the DB column it
 * names, and the `::jsonb`-cast text to emit for it. `null` for a token this
 * helper does not rewrite: empty, already cast, a function call or foreign-table
 * path (parens/dots), or a name belonging to no encrypted column.
 */
function resolveSelectToken(
  trimmed: string,
  propToDb: Record<string, string>,
  dbNames: ReadonlySet<string>,
): { key: string; db: string; emit: string } | null {
  if (!trimmed) return null
  if (trimmed.includes('::')) return null
  if (trimmed.includes('(') || trimmed.includes('.')) return null

  // Already-aliased token: `alias:column`
  const aliasMatch = trimmed.match(
    /^([A-Za-z_][A-Za-z0-9_]*):([A-Za-z_][A-Za-z0-9_]*)$/,
  )
  if (aliasMatch) {
    const [, alias, name] = aliasMatch
    const db =
      lookupDbName(propToDb, name) ?? (dbNames.has(name) ? name : undefined)
    if (db === undefined) return null
    return { key: alias, db, emit: `${alias}:${db}::jsonb` }
  }

  const db = lookupDbName(propToDb, trimmed)
  if (db !== undefined) {
    return {
      key: trimmed,
      db,
      emit: db === trimmed ? `${trimmed}::jsonb` : `${trimmed}:${db}::jsonb`,
    }
  }

  if (dbNames.has(trimmed)) {
    return { key: trimmed, db: trimmed, emit: `${trimmed}::jsonb` }
  }

  return null
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
    // `matches` is the encrypted free-text (bloom) operator. `contains` is
    // plaintext-native on scalar columns, but on an encrypted `types.Json`
    // column it IS the encrypted ste_vec containment (#650) — the v3 dialect's
    // capability resolver re-types the collected term to `searchableJson` when
    // the column carries that capability instead of `freeTextSearch`.
    case 'contains':
    case 'matches':
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
  const parts = splitTopLevel(orString)

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
    const parsedValue = parseOrValue(value, op)

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
const CONTAINMENT_OPS = new Set(['contains', 'matches', 'cs'])

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
  return op === 'contains' || op === 'matches' ? 'cs' : op
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

/** A logic-group token: the only non-operand position an opener may follow. */
const OR_GROUP_TOKEN = /^(?:not\.)?(?:and|or)$/

/**
 * Split on the commas that separate top-level tokens, leaving those inside a
 * quoted operand or a `(…)` / `{…}` literal alone.
 *
 * Quotes are tracked at EVERY depth. A quoted string is opaque wherever it
 * appears, and an array literal quotes any element carrying a reserved character
 * (see {@link arrayLiteralElement}) — so `{"a}b"}` closes at the LAST brace, not
 * the one inside the element. Tracking quotes only at depth 0 ended the literal
 * early and swallowed the following condition into this operand.
 *
 * Braces and parens count as STRUCTURE only where PostgREST's grammar can put
 * them: opening a logic group (`and(`, `or(`, and their `not.` forms), opening
 * an operand (immediately after the operator dot — `col.cs.{…}`, `col.in.(…)`),
 * or nested inside a literal already open. `}` and `)` are not PostgREST
 * reserved characters and `{`/`(` are not reserved mid-operand, so `a}b` and
 * `a{b` are valid unquoted scalars. Counting those as structure desynchronised
 * the split: a stray closer drove `depth` negative and a stray opener stranded
 * it above zero, and either way no later comma split — every remaining condition
 * was silently absorbed into this operand.
 *
 * `current === ''` admits a literal at the start of a token, which is how the
 * `in`-list reuse below sees `{"a":1},{"b":2}`.
 *
 * The rule still reads a `{` after an in-value dot (`x.eq.a.{b`) as an operand
 * opener. `depth !== 0` at the end proves the counting was fooled, so the pass
 * is discarded and the input re-split honouring quotes alone — a backstop, not
 * the primary mechanism. It must stay narrow: applied to an input whose braces
 * WERE structure, it re-splits inside `{vip,admin}` and `parseOrString` then
 * drops the dotless `admin}` fragment.
 *
 * `trackDepth` is the recursion's own flag, never passed by callers. NEVER
 * throws — `query-builder.ts` relies on `parseOrString` being total so that
 * capability errors surface in filter order.
 */
function splitTopLevel(input: string, trackDepth = true): string[] {
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
    } else if (char === '"') {
      inQuotes = !inQuotes
      current += char
    } else if (
      trackDepth &&
      (char === '(' || char === '{') &&
      !inQuotes &&
      // `{` as well as `(`: a containment operand is an array (`{vip,admin}`) or
      // a jsonb (`{"a":1,"b":2}`) literal, whose top-level commas are part of
      // the value. PostgREST's own logic-tree parser tracks these braces;
      // without them a condition splits mid-literal into `tags.cs.{vip` and a
      // dotless fragment `admin}` that the loop below silently drops. Only at a
      // token boundary, though — mid-operand the character is just data.
      (depth > 0 ||
        current === '' ||
        current.endsWith('.') ||
        OR_GROUP_TOKEN.test(current))
    ) {
      depth++
      current += char
    } else if (
      trackDepth &&
      (char === ')' || char === '}') &&
      !inQuotes &&
      depth > 0
    ) {
      depth -= 1
      current += char
    } else if (char === ',' && depth === 0 && !inQuotes) {
      parts.push(current)
      current = ''
    } else {
      current += char
    }
  }

  parts.push(current)

  // An opener that was never structure (`note.eq.a{b,…`) left depth stranded and
  // swallowed every condition behind it. Re-split without depth: quotes alone.
  if (trackDepth && depth !== 0) return splitTopLevel(input, false)

  return parts
}

/**
 * One element of an `in`-list operand, undoing {@link formatOrValue}'s quoting.
 * Unquoted elements are trimmed, as PostgREST ignores whitespace around them;
 * inside quotes it is significant.
 */
function parseInListElement(element: string): string {
  const trimmed = element.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return unescapeOrValue(trimmed.slice(1, -1))
  }
  return trimmed
}

/**
 * PostgREST operators whose operand is delimited by parentheses: the `in` list
 * and the range operators. Everywhere else `(` is an ordinary character, and a
 * parenthesized operand is a scalar that happens to start with one.
 *
 * The range operators earn their place by round-trip fidelity rather than by
 * encryption: none is supported on an encrypted column, but an or-string is
 * rebuilt whole as soon as ANY of its conditions names one, so a plaintext
 * `period.ov.(1,10)` sharing the group must re-emit byte-for-byte.
 */
const PAREN_OPERAND_OPS = new Set(['in', 'ov', 'sl', 'sr', 'nxr', 'nxl', 'adj'])

/**
 * @param op the operator the value belongs to, already stripped of any `not.`
 * prefix. Parsing a parenthesized scalar as an array meant an encrypted `eq`
 * operand was encrypted as a JS array rather than the intended string, and the
 * filter matched nothing.
 */
function parseOrValue(value: string, op?: string): unknown {
  // Handle double-quoted values (PostgREST quoting for reserved characters).
  // Must undo `escapeOrValue`, or a parse → rebuild round-trip doubles every
  // backslash. The two functions are only correct as a pair.
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return unescapeOrValue(value.slice(1, -1))
  }

  // Handle parenthesized lists: (val1,val2,val3). Elements are quoted exactly as
  // any other operand, so the split must respect those quotes: `("a,b",c)` is
  // two elements, not three.
  if (
    op !== undefined &&
    PAREN_OPERAND_OPS.has(op) &&
    value.startsWith('(') &&
    value.endsWith(')')
  ) {
    return splitTopLevel(value.slice(1, -1)).map(parseInListElement)
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

/**
 * The reserved set for a SCALAR operand: {@link POSTGREST_RESERVED} plus the
 * braces.
 *
 * A brace is structure to PostgREST's logic-tree parser inside `or=(…)`, and to
 * {@link splitTopLevel} on the way back in, so an unquoted `a{b` is malformed on
 * the wire AND desynchronises our own parse — the condition behind it is absorbed
 * into this operand and silently dropped. Every character the parser reacts to
 * must be quoted here.
 *
 * Deliberately NOT used for containment literals: those are `{…}` by
 * construction, and quoting them on the brace alone would turn `tags.cs.{vip}`
 * into `tags.cs."{vip}"`. Both spellings parse, but the bare one is what
 * PostgREST documents and what the tests pin.
 */
const POSTGREST_RESERVED_SCALAR = /["\\,(){}.]/

/**
 * Operands PostgREST reads as SQL values rather than as the string spelling
 * them. A STRING operand that happens to spell one must be quoted, or
 * `name.eq.null` compares against SQL NULL — a filter that matches nothing —
 * instead of against the three-character string.
 */
const POSTGREST_RESERVED_WORDS = new Set(['null', 'true', 'false'])

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
    // Quoted on the NARROW set, not the scalar one: a containment literal is
    // always brace-delimited, so the scalar set would quote every one of them.
    // Its own braces are balanced and `splitTopLevel` counts them correctly.
    if (literal !== null) {
      return POSTGREST_RESERVED.test(literal)
        ? `"${escapeOrValue(literal)}"`
        : literal
    }
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
  if (
    POSTGREST_RESERVED_SCALAR.test(str) ||
    POSTGREST_RESERVED_WORDS.has(str)
  ) {
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

/**
 * The operand for a direct `cs`/`contains` filter: `{a,b}` for an array,
 * `{"a":1}` for a jsonb object, `null` for a scalar.
 *
 * `null` means "not a structured operand" — the caller forwards the value as it
 * stands. That covers both a plaintext string (`cs.plain`) and the v3 encrypted
 * envelope, which is already `JSON.stringify`d and must not be re-serialized.
 *
 * Required because postgrest-js builds an array operand as `{${value.join(',')}}`
 * with no element quoting, so an element carrying a comma becomes two elements;
 * and its `not()` stringifies the operand outright, dropping the braces and
 * rendering an object as `[object Object]`. The `.or()` path formats containment
 * operands through the same {@link containmentLiteral}; emit them identically
 * here, or the two paths disagree on what the same call means.
 */
export function formatContainmentOperand(value: unknown): string | null {
  return containmentLiteral(value)
}
