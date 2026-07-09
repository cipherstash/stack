import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { QueryTypeName } from '@/types'
import type { FilterOp, PendingOrCondition } from './types'

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
): string {
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
    .join(',')
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
): string {
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
    .join(',')
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
 * Output: `[{ column: 'email', op: 'eq', value: 'john@example.com' }, { column: 'name', op: 'ilike', value: '%john%' }]`
 */
export function parseOrString(orString: string): PendingOrCondition[] {
  const conditions: PendingOrCondition[] = []
  // Split on commas that are not inside parentheses (nested or/and)
  const parts = splitOrString(orString)

  for (const part of parts) {
    const trimmed = part.trim()
    if (!trimmed) continue

    // Format: column.op.value
    const firstDot = trimmed.indexOf('.')
    if (firstDot === -1) continue

    const column = trimmed.slice(0, firstDot)
    const rest = trimmed.slice(firstDot + 1)

    const secondDot = rest.indexOf('.')
    if (secondDot === -1) continue

    const op = rest.slice(0, secondDot) as FilterOp
    const value = rest.slice(secondDot + 1)

    // Handle special value formats
    const parsedValue = parseOrValue(value)

    conditions.push({ column, op, value: parsedValue })
  }

  return conditions
}

/**
 * Rebuild an `.or()` string from structured conditions.
 */
export function rebuildOrString(conditions: PendingOrCondition[]): string {
  return conditions
    .map((c) => {
      const value = formatOrValue(c.value)
      return `${c.column}.${c.op}.${value}`
    })
    .join(',')
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function splitOrString(input: string): string[] {
  const parts: string[] = []
  let current = ''
  let depth = 0
  let inQuotes = false

  for (const char of input) {
    if (char === '"' && depth === 0) {
      inQuotes = !inQuotes
      current += char
    } else if (char === '(' && !inQuotes) {
      depth++
      current += char
    } else if (char === ')' && !inQuotes) {
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
  // Handle double-quoted values (PostgREST quoting for reserved characters)
  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1)
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
 * PostgREST reserved characters that require double-quoting in filter values.
 * See: https://docs.postgrest.org/en/latest/references/api/tables_views.html
 */
const POSTGREST_RESERVED = /[,().]/

function formatOrValue(value: unknown): string {
  if (Array.isArray(value)) {
    return `(${value.join(',')})`
  }
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'

  const str = String(value)

  // Wrap in double quotes if the value contains reserved characters.
  // This is required for encrypted values (JSON with commas, braces, etc.)
  // and is safe for all string values per PostgREST spec.
  if (POSTGREST_RESERVED.test(str)) {
    return `"${str}"`
  }

  return str
}
