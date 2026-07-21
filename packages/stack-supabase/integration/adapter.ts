import { encryptedTable } from '@cipherstash/stack/eql/v3'
import {
  databaseUrl,
  type IntegrationAdapter,
  type PlainRow,
  type QueryOp,
  type QueryOpKind,
  type TableSpec,
} from '@cipherstash/test-kit'
import postgres from 'postgres'
import { encryptedSupabaseV3 } from '../src/index.js'
import { makePostgrestClient, reloadSchemaCache } from './helpers/pgrest'

/**
 * The Supabase v3 adapter under real ZeroKMS ciphertext.
 *
 * Built through the PUBLIC `encryptedSupabaseV3` factory, so the shipped
 * construction path runs: introspection over `pg`, declared-schema verification
 * against the live domains, and a real `Encryption({ eqlVersion: 3 })` client.
 * A hand-assembled builder would skip all three.
 *
 * The table therefore has to exist before the instance is constructed —
 * introspection reads it — which is why `createTable` also builds the client.
 */

/**
 * `order` is supported. The builder rewrites an encrypted ordering column to the
 * jsonb path `col->op`, which selects the OPE term; OPE is order-preserving, so
 * PostgREST reproduces the plaintext order. Columns with no ordering term are
 * rejected by the capability matrix, exactly like `gt`/`lt`.
 */
const SUPPORTED_OPS: ReadonlySet<QueryOpKind> = new Set([
  'eq',
  'ne',
  'in',
  'notIn',
  'gt',
  'gte',
  'lt',
  'lte',
  'between',
  'notBetween',
  'isNull',
  'isNotNull',
  'order',
])

/**
 * EQL 3.0.2 requires a typed query-domain operand for encrypted free-text
 * matching. PostgREST cannot express that cast, so matching is rejected on
 * every encrypted column even when its domain carries the capability.
 */
const ALWAYS_REJECTED: ReadonlySet<QueryOpKind> = new Set(['matches'])

type Instance = Awaited<ReturnType<typeof encryptedSupabaseV3>>

// biome-ignore lint/suspicious/noExplicitAny: the builder is generic over a row type the driver does not know
type Query = any

export function makeSupabaseAdapter(): IntegrationAdapter {
  let sql: postgres.Sql
  let instance: Instance
  let tableName: string

  const from = (): Query => instance.from(tableName)

  /** Apply `op` to a `select('row_key')` query. May throw synchronously — the
   * capability and ordering guards fire at call time, not on execute. */
  const applyOp = (op: QueryOp): Query => {
    const q = from().select('row_key')
    switch (op.kind) {
      case 'eq':
        return q.eq(op.column, op.value)
      case 'ne':
        return q.neq(op.column, op.value)
      case 'gt':
        return q.gt(op.column, op.value)
      case 'gte':
        return q.gte(op.column, op.value)
      case 'lt':
        return q.lt(op.column, op.value)
      case 'lte':
        return q.lte(op.column, op.value)
      case 'in':
        // Two distinct code paths: `.in()` and the raw `.filter(col, 'in', […])`.
        // The raw one encrypted the whole list as a single term until recently,
        // so both must be proven against the same oracle.
        return op.asRawFilter
          ? q.filter(op.column, 'in', [...op.values])
          : q.in(op.column, [...op.values])
      case 'notIn':
        return q.not(op.column, 'in', [...op.values])
      case 'between':
        // The builder exposes no `between`; it is `gte AND lte` by definition.
        return q.gte(op.column, op.lo).lte(op.column, op.hi)
      case 'notBetween':
        // Structured `.or()`, not an or-STRING: a string operand would have to
        // stringify Dates and bigints, and the parser would then have to guess
        // them back. The structured form carries the plaintext through intact.
        return q.or([
          { column: op.column, op: 'lt', value: op.lo },
          { column: op.column, op: 'gt', value: op.hi },
        ])
      case 'matches':
        return q.matches(op.column, op.needle)
      case 'isNull':
        return q.is(op.column, null)
      case 'isNotNull':
        return q.not(op.column, 'is', null)
      case 'order':
        // Exclude the all-NULL row: NULL ordering is a property of the SQL
        // dialect, not of the encrypted ordering term, and the oracle sorts
        // value rows only.
        //
        // The secondary sort on `row_key` is load-bearing. A domain with fewer
        // distinct samples than rows gives two rows the SAME plaintext, so the
        // encrypted term alone does not determine their order — the oracle
        // breaks such ties on `row_key` ascending, and the query must mirror it
        // or the test flakes rather than proving ordering. (date/timestamp have
        // two samples across three rows; the numeric families have four.)
        return q
          .not(op.column, 'is', null)
          .order(op.column, { ascending: op.direction === 'asc' })
          .order('row_key', { ascending: true })
    }
  }

  return {
    name: 'supabase',
    supportedOps: SUPPORTED_OPS,
    alwaysRejectedOps: ALWAYS_REJECTED,
    // `.in()` and the raw `.filter(col, 'in', […])` are different code paths.
    hasRawInListPath: true,

    async setup() {
      sql = postgres(databaseUrl(), { prepare: false })
    },

    async teardown() {
      if (tableName) await sql.unsafe(`DROP TABLE IF EXISTS ${tableName}`)
      await sql.end()
    },

    async createTable(table: TableSpec) {
      tableName = table.name

      const columns = table.columns
        .map((column) => `"${column.slug}" ${column.eqlType}`)
        .join(',\n        ')

      await sql.unsafe(`DROP TABLE IF EXISTS ${table.name}`)
      await sql.unsafe(`
        CREATE TABLE ${table.name} (
          row_key TEXT PRIMARY KEY,
          ${columns}
        )
      `)
      // The EQL grants cover `eql_v3` objects, not application tables. PostgREST
      // runs as `anon`; without this every query is a 401.
      await sql.unsafe(
        `GRANT SELECT, INSERT, UPDATE, DELETE ON ${table.name} TO anon, authenticated`,
      )
      await reloadSchemaCache(sql, table.name)

      const schema = encryptedTable(
        table.name,
        Object.fromEntries(
          table.columns.map((column) => [
            column.slug,
            column.spec.builder(column.slug),
          ]),
        ) as never,
      )

      // `schemas` is a Record keyed by table name, not an array — the factory
      // rejects a key that disagrees with the table's own name.
      instance = await encryptedSupabaseV3(makePostgrestClient(), {
        schemas: { [table.name]: schema } as never,
        databaseUrl: databaseUrl(),
      })
    },

    async insertSingle(_table: TableSpec, row: PlainRow) {
      // A single object routes through `encryptModel`; an array routes through
      // `bulkEncryptModels`. Both must be exercised.
      const { error } = await from().insert({
        row_key: row.rowKey,
        ...row.values,
      })
      if (error)
        throw new Error(`insertSingle(${row.rowKey}): ${error.message}`)
    },

    async insertBulk(_table: TableSpec, rows: readonly PlainRow[]) {
      const models = rows.map((row) => ({ row_key: row.rowKey, ...row.values }))
      const { error } = await from().insert(models)
      if (error) throw new Error(`insertBulk: ${error.message}`)
    },

    async run(_table: TableSpec, op: QueryOp): Promise<string[]> {
      const { data, error } = await applyOp(op)
      if (error) throw new Error(`${op.kind}(${op.column}): ${error.message}`)
      return (data as { row_key: string }[]).map((row) => row.row_key)
    },

    async expectRejected(_table: TableSpec, op: QueryOp) {
      // The rejection fires in one of two places: a capability check throws
      // synchronously while collecting terms (marked `[supabase v3]`), or a term
      // that reaches `execute` comes back as a Result error. Accept either — but
      // NOT an arbitrary throw. A `TypeError` while assembling the term, or a
      // network failure, is not the refusal this test asserts; counting it would
      // let the test pass for the wrong reason if the real capability guard were
      // removed. The `try` wraps only `applyOp`, and the "not rejected" error is
      // thrown OUTSIDE it, so it can never be swallowed as a rejection.
      let error: { message: string } | null
      try {
        ;({ error } = await applyOp(op))
      } catch (cause) {
        if (cause instanceof Error && cause.message.includes('[supabase v3]')) {
          return // a modeled capability rejection
        }
        throw cause // an unexpected error — fail loudly
      }
      if (error) return // an execute-time DB refusal (e.g. a PostgREST error)
      throw new Error(
        `Expected ${op.kind}("${op.column}") to be rejected, but it succeeded`,
      )
    },
  }
}
