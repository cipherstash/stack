/**
 * `IntegrationAdapter` over `@cipherstash/stack/wasm-inline` (#662) — runs the
 * shared v3 family suite against the WASM entry, giving `encryptQuery` /
 * `encryptQueryBulk` the same per-domain live row-matching coverage the
 * Drizzle/Supabase adapters have.
 *
 * The WASM surface mints terms only (no operator builder, no model helpers),
 * so this adapter IS the SQL layer: inserts encrypt per-field via
 * `client.encrypt`, and every query op renders the documented raw-SQL shape —
 * `eql_v3.<fn>(col, $n::jsonb::eql_v3.query_<domain>)` — that edge consumers
 * hand-write. Passing here proves the whole recipe end to end: WASM-minted
 * term → query-domain cast → indexed operator → correct row set.
 *
 * The SQL shapes deliberately mirror the Drizzle v3 dialect
 * (`packages/stack-drizzle/src/v3/sql-dialect.ts`): `eq`/`neq`, comparison
 * fns, parenthesised `gte AND lte` ranges, `contains` for bloom matching, and
 * `ord_term` ordering. `in`/`notIn` decompose to OR-of-eq / AND-of-neq over
 * one `encryptQueryBulk` batch — exercising the bulk path on every family.
 */

import type {
  IntegrationAdapter,
  Plain,
  PlainRow,
  QueryOp,
  QueryOpKind,
  TableSpec,
} from '@cipherstash/test-kit'
import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { type AnyV3Table, encryptedTable } from '@/eql/v3'
import type { BuildableV3QueryableColumn } from '@/types'
import {
  Encryption as WasmEncryption,
  type WasmEncryptionClient,
  type WasmPlaintext,
} from '@/wasm-inline'

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
  'matches',
  'order',
  'isNull',
  'isNotNull',
])

/**
 * The WASM factory has no auto/dev-profile strategy (#663): it hard-requires
 * explicit credentials, so — unlike the native adapters, where a
 * `~/.cipherstash` profile satisfies the gate — this adapter needs the four
 * `CS_*` variables themselves. Fail loud, per the harness doctrine.
 */
function requireWasmCreds() {
  const keys = [
    'CS_WORKSPACE_CRN',
    'CS_CLIENT_ACCESS_KEY',
    'CS_CLIENT_ID',
    'CS_CLIENT_KEY',
  ] as const
  const missing = keys.filter((k) => !process.env[k])
  if (missing.length > 0) {
    throw new Error(
      `WASM integration adapter: missing ${missing.join(', ')}. The ` +
        '`@cipherstash/stack/wasm-inline` factory requires explicit ' +
        'credentials (no dev-profile fallback — see #663), so the CS_* ' +
        'variables must be set even when a ~/.cipherstash profile exists.',
    )
  }
  return {
    workspaceCrn: process.env.CS_WORKSPACE_CRN as string,
    accessKey: process.env.CS_CLIENT_ACCESS_KEY as string,
    clientId: process.env.CS_CLIENT_ID as string,
    clientKey: process.env.CS_CLIENT_KEY as string,
  }
}

/**
 * `WasmPlaintext` has no `Date` arm (the WASM boundary serializes via serde,
 * which doesn't consult `toJSON`) — send date/timestamp values as ISO
 * strings, the same wire form the native SDK's `Date` handling produces.
 */
function toWasmPlaintext(value: Plain): WasmPlaintext {
  return value instanceof Date ? value.toISOString() : value
}

/**
 * Unwrap a `Result` from the WASM client, throwing on failure.
 *
 * The client returns `{ data } | { failure }` on every fallible method (the
 * repo-wide contract — see `AGENTS.md`). This harness wants a failure to abort
 * the run loudly with the SDK's own message, so it unwraps at the call site
 * rather than threading Results through the query builders.
 */
function unwrap<T>(
  result:
    | { data: T; failure?: never }
    | { data?: never; failure: { message: string } },
  op: string,
): T {
  if (result.failure) {
    throw new Error(`[wasm adapter]: ${op} failed — ${result.failure.message}`)
  }
  return result.data as T
}

/** `public.eql_v3_text_eq` → `eql_v3.query_text_eq`; irregular: json → jsonb. */
function queryDomain(eqlType: string): string {
  const suffix = eqlType.replace(/^public\.eql_v3_/, '')
  return suffix === 'json' ? 'eql_v3.query_json' : `eql_v3.query_${suffix}`
}

const QUERY_TYPE_BY_KIND = {
  eq: 'equality',
  ne: 'equality',
  in: 'equality',
  notIn: 'equality',
  gt: 'orderAndRange',
  gte: 'orderAndRange',
  lt: 'orderAndRange',
  lte: 'orderAndRange',
  between: 'orderAndRange',
  notBetween: 'orderAndRange',
  matches: 'freeTextSearch',
} as const

type ColumnEntry = {
  column: BuildableV3QueryableColumn
  eqlType: string
}

export function makeWasmAdapter(): IntegrationAdapter {
  const creds = requireWasmCreds()

  let sql: postgres.Sql
  let tableName = ''
  let client: WasmEncryptionClient
  let tableSchema: AnyV3Table
  let columns: Record<string, ColumnEntry> = {}

  function col(slug: string): ColumnEntry {
    const entry = columns[slug]
    if (!entry) throw new Error(`Unknown column slug "${slug}"`)
    return entry
  }

  /** Mint one term and pair it with its query-domain cast. */
  async function term(
    slug: string,
    value: Plain,
    kind: keyof typeof QUERY_TYPE_BY_KIND,
  ): Promise<{ param: unknown; cast: string }> {
    const { column, eqlType } = col(slug)
    const encrypted = unwrap(
      await client.encryptQuery(toWasmPlaintext(value), {
        table: tableSchema,
        column,
        queryType: QUERY_TYPE_BY_KIND[kind],
      }),
      'encryptQuery',
    )
    return { param: encrypted, cast: queryDomain(eqlType) }
  }

  // Payload params are bound as RAW OBJECTS, never pre-stringified. The
  // `$n::jsonb` casts make the server type those params as jsonb, and
  // postgres.js serializes jsonb params with JSON.stringify — so a
  // pre-stringified payload gets stringified AGAIN, arriving as a jsonb
  // *string* scalar that fails every `jsonb_typeof(VALUE) = 'object'`
  // domain CHECK. (Reproduced against postgres-eql with a hand-valid
  // envelope; psql accepts what the double-encoded binding does not.)
  async function selectKeys(
    where: string,
    params: readonly unknown[],
    orderBy = 'row_key ASC',
  ): Promise<string[]> {
    const rows = await sql.unsafe(
      `SELECT row_key FROM ${tableName} WHERE ${where} ORDER BY ${orderBy}`,
      params as never[],
    )
    return rows.map((r) => (r as { row_key: string }).row_key)
  }

  async function insertRow(assignments: Record<string, unknown>) {
    const keys = Object.keys(assignments)
    const colList = keys.map((k) => `"${k}"`).join(', ')
    const placeholders = keys
      .map((k, i) => (k === 'row_key' ? `$${i + 1}` : `$${i + 1}::jsonb`))
      .join(', ')
    // Raw objects, NOT pre-stringified — see the serializer note on
    // `selectKeys`. postgres.js JSON-encodes them exactly once for the
    // jsonb-typed placeholders.
    const params = keys.map((k) => assignments[k])
    try {
      await sql.unsafe(
        `INSERT INTO ${tableName} (${colList}) VALUES (${placeholders})`,
        params as never[],
      )
    } catch (cause) {
      // Echo what actually reached the driver: `assertWireEnvelope` has
      // already vouched for the JS-side shape, so a domain-CHECK failure
      // here implicates the SQL binding, and the exact params are the
      // evidence. Ciphertext only — EQL payloads never contain plaintext.
      throw new Error(
        `INSERT into ${tableName} failed for row "${assignments['row_key']}". ` +
          `Bound params (truncated): ${params.map((p) => JSON.stringify(p)?.slice(0, 160)).join(' | ')}`,
        { cause },
      )
    }
  }

  /**
   * Pin the JS-side shape of a storage payload BEFORE it goes anywhere near
   * SQL. The wasm boundary (serde-wasm-bindgen) can produce values that
   * round-trip through the FFI fine but collapse under `JSON.stringify` —
   * e.g. a JS `Map` stringifies to `{}` — and the resulting Postgres
   * domain-CHECK error names the column's domain, not the cause. Failing
   * here instead names the payload.
   */
  function assertWireEnvelope(slug: string, payload: unknown): void {
    const json = JSON.stringify(payload)
    const wire = json === undefined ? undefined : JSON.parse(json)
    const ok =
      wire !== null &&
      typeof wire === 'object' &&
      !Array.isArray(wire) &&
      String(wire.v) === '3' &&
      'i' in wire &&
      'c' in wire
    if (!ok) {
      throw new Error(
        `WASM encrypt for column "${slug}" did not produce a JSON-stringifiable v3 envelope. ` +
          `typeof=${typeof payload}, ctor=${(payload as object)?.constructor?.name}, ` +
          `isMap=${payload instanceof Map}, ` +
          `ownKeys=[${payload && typeof payload === 'object' ? Object.keys(payload).join(', ') : ''}], ` +
          `wire=${String(json).slice(0, 300)}`,
      )
    }
  }

  async function encryptRow(row: PlainRow): Promise<Record<string, unknown>> {
    const assignments: Record<string, unknown> = { row_key: row.rowKey }
    // Field encrypts are independent ZeroKMS round-trips — run them
    // concurrently rather than paying fields × RTT per row.
    await Promise.all(
      Object.entries(row.values).map(async ([slug, value]) => {
        const encrypted = unwrap(
          await client.encrypt(toWasmPlaintext(value), {
            table: tableSchema,
            column: col(slug).column,
          }),
          'encrypt',
        )
        assertWireEnvelope(slug, encrypted)
        assignments[slug] = encrypted
      }),
    )
    return assignments
  }

  async function run(op: QueryOp): Promise<string[]> {
    switch (op.kind) {
      case 'eq':
      case 'ne':
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte': {
        const fn = op.kind === 'ne' ? 'neq' : op.kind
        const t = await term(op.column, op.value, op.kind)
        return selectKeys(
          `eql_v3.${fn}("${op.column}", $1::jsonb::${t.cast})`,
          [t.param],
        )
      }
      case 'in':
      case 'notIn': {
        // Parity with the production operators (drizzle inArrayOp): an
        // empty list would otherwise render `WHERE ()` — a syntax error,
        // not empty-IN semantics.
        if (op.values.length === 0) {
          throw new Error(`${op.kind} requires a non-empty list of values`)
        }
        // One encryptQueryBulk crossing for the whole list — the bulk path
        // gets exercised on every family this way.
        const { column, eqlType } = col(op.column)
        const encrypted = unwrap(
          await client.encryptQueryBulk(
            op.values.map((value) => ({
              value: toWasmPlaintext(value),
              table: tableSchema,
              column,
              queryType: 'equality' as const,
            })),
          ),
          'encryptQueryBulk',
        )
        const cast = queryDomain(eqlType)
        const fn = op.kind === 'in' ? 'eq' : 'neq'
        const joiner = op.kind === 'in' ? ' OR ' : ' AND '
        const clauses = encrypted.map(
          (_, i) => `eql_v3.${fn}("${op.column}", $${i + 1}::jsonb::${cast})`,
        )
        return selectKeys(`(${clauses.join(joiner)})`, encrypted)
      }
      case 'between':
      case 'notBetween': {
        const [lo, hi] = await Promise.all([
          term(op.column, op.lo, op.kind),
          term(op.column, op.hi, op.kind),
        ])
        // Parenthesised conjunction, mirroring the Drizzle dialect's
        // load-bearing parentheses (NOT binds tighter than AND).
        const range = `(eql_v3.gte("${op.column}", $1::jsonb::${lo.cast}) AND eql_v3.lte("${op.column}", $2::jsonb::${hi.cast}))`
        return selectKeys(op.kind === 'between' ? range : `NOT ${range}`, [
          lo.param,
          hi.param,
        ])
      }
      case 'matches': {
        const t = await term(op.column, op.needle, 'matches')
        return selectKeys(
          `eql_v3.matches("${op.column}", $1::jsonb::${t.cast})`,
          [t.param],
        )
      }
      case 'order': {
        // OPE ordering (`ord_term`) — the block-ORE domains are deferred in
        // the catalog, so `ord_term_ore` never applies here. The secondary
        // `row_key ASC` mirrors the oracle's tie-break: domains with fewer
        // samples than rows (date/timestamp have two) guarantee tied values,
        // and without it the tied rows come back in arbitrary order.
        return selectKeys(
          `"${op.column}" IS NOT NULL`,
          [],
          `eql_v3.ord_term("${op.column}") ${op.direction.toUpperCase()}, row_key ASC`,
        )
      }
      case 'isNull':
        return selectKeys(`"${op.column}" IS NULL`, [])
      case 'isNotNull':
        return selectKeys(`"${op.column}" IS NOT NULL`, [])
    }
  }

  return {
    name: 'wasm',
    supportedOps: SUPPORTED_OPS,
    alwaysRejectedOps: new Set(),

    async setup() {
      sql = postgres(databaseUrl(), { prepare: false })
    },

    async teardown() {
      if (tableName) await sql.unsafe(`DROP TABLE IF EXISTS ${tableName}`)
      await sql.end()
    },

    async createTable(spec: TableSpec) {
      tableName = spec.name

      const cols = Object.fromEntries(
        spec.columns.map((c) => [c.slug, c.spec.builder(c.slug)]),
      )
      tableSchema = encryptedTable(spec.name, cols as never)
      columns = Object.fromEntries(
        spec.columns.map((c) => [
          c.slug,
          {
            column: (
              tableSchema as unknown as Record<string, ColumnEntry['column']>
            )[c.slug],
            eqlType: c.eqlType,
          },
        ]),
      )

      // DDL comes from the column builders, not a hand-written list, so a
      // domain rename cannot silently desync the table from the schema.
      const ddl = spec.columns
        .map((c) => `"${c.slug}" ${c.eqlType}`)
        .join(',\n          ')
      await sql.unsafe(`DROP TABLE IF EXISTS ${spec.name}`)
      await sql.unsafe(`
        CREATE TABLE ${spec.name} (
          row_key TEXT PRIMARY KEY,
          ${ddl}
        )
      `)

      // Rebuilt per family — the factory pins the schema set at construction.
      client = await WasmEncryption({
        schemas: [tableSchema],
        config: creds,
      })
    },

    // The WASM entry has no model helpers (encryptModel/bulkEncryptModels
    // live on the Node client), so BOTH insert paths encrypt per field via
    // `encrypt` — the surface an edge function actually has. The kit's
    // single/bulk split still runs; it just exercises the same primitive.
    async insertSingle(_spec: TableSpec, row: PlainRow) {
      await insertRow(await encryptRow(row))
    },

    async insertBulk(_spec: TableSpec, rows: readonly PlainRow[]) {
      // Rows are independent (distinct row_key PKs, no ordering
      // dependency) — encrypt and insert them concurrently.
      await Promise.all(
        rows.map(async (row) => insertRow(await encryptRow(row))),
      )
    },

    async run(_spec: TableSpec, op: QueryOp) {
      return run(op)
    },

    // Discriminate capability rejections from infrastructure failures —
    // this adapter's run() path is fully live (ZeroKMS + real SQL), so a
    // bare catch would record a connection reset or a dropped table as a
    // passing negative test. Same doctrine as the Supabase adapter's
    // expectRejected. Two shapes are legitimate rejections here:
    //  - client-side: resolveIndexType / the pre-FFI validators throw when
    //    the queryType isn't configured on the column;
    //  - server-side (order ops only): domains without an ordering index
    //    have no eql_v3.ord_term overload, so Postgres rejects the call.
    async expectRejected(_spec: TableSpec, op: QueryOp) {
      try {
        await run(op)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        const isCapabilityRejection =
          /is not configured on column|has no indexes configured|\[encryption\]:/.test(
            message,
          ) || /ord_term/.test(message)
        if (isCapabilityRejection) return
        throw new Error(
          `Expected ${op.kind} on "${op.column}" to be rejected by a capability error, but got an unrelated failure: ${message}`,
          { cause: error },
        )
      }
      throw new Error(
        `Expected ${op.kind} on "${op.column}" to be rejected, but it ran.`,
      )
    },
  }
}
