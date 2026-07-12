import type { EncryptionClient } from '@/encryption'
import type { AnyV3Table } from '@/eql/v3'
import { DATE_LIKE_CASTS, EncryptedV3Column } from '@/eql/v3/columns'
import type {
  ColumnSchema,
  EncryptedTable,
  EncryptedTableColumn,
} from '@/schema'
import type {
  BuildableQueryColumn,
  QueryTypeName,
  ScalarQueryTerm,
} from '@/types'
import { logger } from '@/utils/logger'
import { addJsonbCastsV3, selectKeyToDbV3 } from './helpers'
import {
  EncryptedQueryBuilderImpl,
  EncryptionFailedError,
} from './query-builder'
import type {
  DbName,
  DbSelect,
  FilterOp,
  SupabaseClientLike,
  SupabaseQueryBuilder,
} from './types'

/** cast_as kinds that reconstruct to a JS `Date` — shared with the typed v3
 * client's decrypt-model path (see `encryption/v3.ts`). */
const DATE_LIKE_CAST_SET = new Set<string>(DATE_LIKE_CASTS)

/**
 * The subset of a v3 column builder the dialect relies on. Structural rather
 * than the concrete class union so the runtime `instanceof EncryptedV3Column`
 * gate and this type stay independent.
 */
type V3ColumnLike = {
  getName(): string
  getEqlType(): string
  getQueryCapabilities(): {
    equality: boolean
    orderAndRange: boolean
    freeTextSearch: boolean
  }
  build(): ColumnSchema
}

/**
 * Reject a declared property name that is also a DIFFERENT physical column.
 *
 * `select('*')` expands the introspected DB names into property names, so a
 * column renamed `created_at → createdAt` and a distinct plaintext column
 * literally named `createdAt` both emit the token `createdAt`, which
 * `addJsonbCastsV3` turns into `createdAt:created_at::jsonb` — twice. PostgREST
 * returns the encrypted column under that key and the plaintext one is never
 * selected, silently yielding the wrong value for a field the row type
 * guarantees.
 *
 * Nothing downstream can disambiguate the two, and `EncryptedTable.build()`'s
 * duplicate check only fires when two BUILDERS share a `getName()`. Refuse to
 * construct instead.
 */
function assertNoPropertyDbNameCollision(
  tableName: string,
  propToDb: Record<string, string>,
  allColumns: string[] | null,
): void {
  if (!allColumns) return
  const dbNames = new Set(allColumns)

  for (const [property, dbName] of Object.entries(propToDb)) {
    if (property === dbName) continue
    if (!dbNames.has(property)) continue
    throw new Error(
      `[supabase v3]: property "${property}" on table "${tableName}" renames DB column "${dbName}", but "${property}" is also a distinct column in the database — the two collide in select('*'). Rename the property, or drop the declared rename.`,
    )
  }
}

/**
 * EQL v3 dialect of {@link EncryptedQueryBuilderImpl} for native concrete-domain
 * columns (`public.*` type domains, `eql_v3` operators). The query mechanism is
 * v2's — direct EQL operators over PostgREST — with four narrow forks:
 *
 * - **Column recognition / naming** — v3 columns are `EncryptedV3Column`
 *   builders and may map a JS property name to a different DB column name
 *   (`buildColumnKeyMap`). Filters, select casts, and mutations resolve
 *   property → DB name; select casts alias the DB column back to the property
 *   (`prop:db_name::jsonb`) so result rows keep property keys.
 * - **Mutation encoding** — the raw encrypted payload object is sent (the
 *   `public.*` domains are `DOMAIN … AS jsonb`), not v2's `{ data: … }`
 *   composite wrap.
 * - **Query-term encoding** — every filter operand is the FULL storage
 *   envelope from `encrypt()`, serialized as jsonb text.
 *
 *   NOT because narrowed terms fail the domain CHECK: the bundle defines a
 *   `public.<domain>_query` companion for each storage domain, whose CHECK
 *   requires `NOT (VALUE ? 'c')` — i.e. it accepts exactly the no-ciphertext
 *   shape `encryptQuery` produces. Those domains are simply unreachable from
 *   here. PostgREST has no syntax to cast a filter VALUE, and an uncast literal
 *   is ambiguous between the `_query` and `jsonb` `@>`/`=` overloads (42725 —
 *   the bundle says so itself, see `cipherstash-encrypt-v3.sql`, the
 *   `_query_types.sql` note). The reachable overload is the `jsonb` one, whose
 *   body coerces its operand to the STORAGE domain, which does require `c`.
 *   (protect-ffi 0.29 can mint narrowed `eql_v3.query_<name>` operands via
 *   `encryptQuery`, but with no way to cast a PostgREST filter value they
 *   stay unreachable from this adapter.)
 *
 *   The full envelope satisfies the storage-domain CHECK by construction, and
 *   the operators extract the term they need (`eq_term`/`ord_term`/
 *   `match_term`).
 * - **`contains`, not `like`/`ilike`** — the v3 domains define no LIKE operator.
 *   Free-text search is TOKEN CONTAINMENT: the bundle declares `@>` on each
 *   match domain (`CREATE OPERATOR @> … FUNCTION = eql_v3.contains`), whose body
 *   is `match_term(a) @> match_term(b)` — `smallint[]` containment of the two
 *   bloom filters. PostgREST reaches it as `cs`.
 *
 *   Match is tokenized + downcased, so `%` is NOT a wildcard — it is tokenized
 *   like any other character, and a `like` pattern is a category error. v3
 *   Drizzle omits `like`/`ilike` for this reason and exposes `contains`; so do
 *   we. The typed builder has no `like`; the runtime methods throw on an
 *   encrypted column and pass through on a plaintext one.
 *
 *   KNOWN BROKEN for real substrings, and not fixable from this file. The
 *   operand is a storage payload, so its bloom carries the whole needle as an
 *   extra `include_original` token, which the haystack's bloom cannot contain
 *   unless the needle equals the stored value or is exactly `token_length` (3)
 *   characters. v3 Drizzle's `contains` has the same defect for the same
 *   reason. Tracked in EQL; do not paper over it here.
 *
 * Decrypted rows additionally get `Date` reconstruction from the
 * encrypt-config `cast_as`, mirroring the typed v3 client.
 */
export class EncryptedQueryBuilderV3Impl<
  T extends Record<string, unknown> = Record<string, unknown>,
> extends EncryptedQueryBuilderImpl<T> {
  private v3Table: AnyV3Table
  /** JS property name → DB column name, for every encrypted column. */
  private propToDb: Record<string, string>
  /** DB column name → JS property name — the inverse of {@link propToDb}, used
   * to expand `select('*')` back into property names. Null prototype: a DB
   * column literally named `constructor` / `toString` would otherwise resolve
   * to an inherited `Object.prototype` member and be emitted as a select token. */
  private dbToProp: Record<string, string>
  /** Built column schemas keyed by DB column name (for `cast_as`). */
  private columnSchemas: Record<string, ColumnSchema>
  /** Column builders keyed by BOTH property name and DB name. */
  private v3Columns: Record<string, V3ColumnLike>

  constructor(
    tableName: string,
    table: AnyV3Table,
    encryptionClient: EncryptionClient,
    supabaseClient: SupabaseClientLike,
    allColumns: string[] | null = null,
  ) {
    super(
      tableName,
      // The base class only ever calls BuildableTable members on the schema
      // (build / encryptModel plumbing); every v2-specific behaviour is
      // overridden below.
      table as unknown as EncryptedTable<EncryptedTableColumn>,
      encryptionClient,
      supabaseClient,
      allColumns,
    )

    this.v3Table = table
    this.propToDb = table.buildColumnKeyMap()
    this.columnSchemas = table.build().columns

    this.dbToProp = Object.create(null) as Record<string, string>
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      this.dbToProp[dbName] = property
    }

    assertNoPropertyDbNameCollision(tableName, this.propToDb, allColumns)

    // Null-prototype: keyed by DB column names, and `validateTransforms` reads
    // it without an own-key guard — an inherited `constructor`/`toString` would
    // otherwise resolve truthy for a plaintext column of that name.
    this.v3Columns = Object.create(null) as Record<string, V3ColumnLike>
    for (const [property, builder] of Object.entries(table.columnBuilders)) {
      if (builder instanceof EncryptedV3Column) {
        const col = builder as unknown as V3ColumnLike
        this.v3Columns[property] = col
        this.v3Columns[col.getName()] = col
      }
    }

    // The base class derives encrypted column names from build(), which v3
    // keys by DB name. Filters and select strings address columns by JS
    // property name, so recognition must cover both.
    this.encryptedColumnNames = Object.keys(this.v3Columns)
  }

  // ---------------------------------------------------------------------------
  // Dialect overrides
  // ---------------------------------------------------------------------------

  protected override getColumnMap(): Record<string, BuildableQueryColumn> {
    return this.v3Columns as unknown as Record<string, BuildableQueryColumn>
  }

  /** Resolve a JS property name to its DB column name. `Object.hasOwn` guards
   * the inherited-member hazard described on {@link EncryptedTable.buildColumnKeyMap}. */
  private dbNameFor(name: string): string {
    return Object.hasOwn(this.propToDb, name) ? this.propToDb[name] : name
  }

  protected override filterColumnName(column: string): DbName {
    return this.dbNameFor(column) as DbName
  }

  /**
   * `ORDER BY` on an OPE-backed column is supported; on every other encrypted
   * column it is rejected.
   *
   * A bare `ORDER BY col` IS wrong. The `*_ord` domains are
   * `CREATE DOMAIN … AS jsonb`, and the bundle declares no btree operator class
   * on any domain — it actively lints against one (`domain_opclass`), because an
   * opclass on a domain bypasses operator resolution. So the sort resolves
   * through jsonb's default `jsonb_cmp` and compares the envelope's keys in
   * storage order, starting at the random ciphertext `c`. No error, and a
   * stable, meaningless row order. (Measured: over 10 rows it returns
   * `r00,r04,r08,r01,…` where the plaintext order is `r00..r09`.)
   *
   * But the correct sort key is reachable without a function call. `eql_v3.ord_term`
   * returns the domain's `op` term, and OPE is order-preserving by construction:
   * ordering by the term reproduces the plaintext order. PostgREST cannot emit
   * `ORDER BY eql_v3.ord_term(col)`, but it CAN emit a jsonb path —
   * `order=col->op.asc` — which selects exactly that term. Measured against a
   * live PostgREST: `order=amount->op.asc` and `.desc` both reproduce the
   * plaintext order for `integer_ord` and `text_search`, over 10 rows.
   *
   * So the guard is on the ordering FLAVOUR, not on encryption:
   *
   * - `ope` present → order by `col->op`. Every plain `_ord` domain, plus
   *   `text_ord` and `text_search`.
   * - `ore` present → reject. The `ob` term is an array of ORE blocks whose
   *   comparison needs the superuser-only opclass; a jsonb-path sort over it is
   *   meaningless. (Such a column cannot hold data on managed Postgres at all:
   *   its domain CHECK raises `ore_domain_unavailable`.)
   * - neither → reject. Storage-only, equality-only and match-only columns
   *   carry no ordering term to sort by.
   *
   * A column absent from {@link v3Columns} is a plaintext passthrough and orders
   * normally. This runtime guard is the only protection the untyped
   * (no-`schemas`) surface has.
   */
  protected override validateTransforms(): void {
    for (const t of this.transforms) {
      if (t.kind !== 'order') continue
      const column = this.v3Columns[t.column]
      if (!column) continue

      const indexes = this.columnSchemas[column.getName()]?.indexes
      if (indexes?.ope) continue

      const reason = indexes?.ore
        ? 'its ORE ordering term (`ob`) needs the superuser-only ORE operator class, which PostgREST cannot reach through a jsonb path'
        : 'it carries no ordering term to sort by'

      throw new Error(
        `[supabase v3]: cannot order by encrypted column "${column.getName()}" (${column.getEqlType()}) — ${reason}. ` +
          'Order by a plaintext column, or use an OPE-backed ordering domain ' +
          '(`*_ord`, `text_ord`, `text_search`), or use the EQL v3 Drizzle integration.',
      )
    }
  }

  /**
   * Encrypted ordering columns sort by their `op` term, not by the envelope.
   *
   * `order=col->op` is the one ordering expression PostgREST can emit that
   * reaches the OPE term. It must NOT leak into filters — those compare whole
   * envelopes through the `eql_v3.*` operators — which is why this is its own
   * seam rather than a change to `filterColumnName`.
   *
   * The canonical EQL form is `ORDER BY eql_v3.ord_term(col)`, which returns
   * `eql_v3_internal.ope_cllw` — a domain over `bytea`, ordered by the native
   * btree. PostgREST cannot call a function, so it orders the `op` term where it
   * sits, inside the envelope. The two agree because the term is what
   * `ord_term()` returns.
   *
   * `->` (jsonb) rather than `->>` (text) keeps the comparison on the typed
   * value. Note this does NOT avoid the database collation: Postgres compares
   * jsonb strings with `varstr_cmp` under the default collation, exactly as it
   * does text. What makes the ordering collation-independent is the term itself
   * — fixed-width lowercase hex (`[0-9a-f]`, 130 chars for `integer_ord`, 82 for
   * `text_search`) — and every collation orders digits before letters and hex
   * letters among themselves. `match-bloom`'s sibling assertion pins that shape.
   *
   * This runs at column-name-mapping time (`transformToDbSpace`), BEFORE
   * `buildAndExecuteQuery` calls `validateTransforms`. For an encrypted column
   * with no `ope` index it therefore returns a bare `dbName` here — a name that
   * would sort by `jsonb_cmp` over the ciphertext if it reached PostgREST — but
   * it never does: `validateTransforms` throws (with a domain-specific reason)
   * before the query executes, so the bare name is only ever an intermediate
   * value on a request that is about to be rejected.
   */
  protected override orderColumnName(column: string): DbName {
    const dbName = this.dbNameFor(column)
    const encrypted = this.v3Columns[column]
    if (!encrypted) return dbName as DbName

    return (
      this.columnSchemas[dbName]?.indexes?.ope ? `${dbName}->op` : dbName
    ) as DbName
  }

  /**
   * Resolve a raw `.filter()` operator to the capability it exercises. Unlike
   * v2, the v3 operand is always the full storage envelope, so `queryType`
   * never selects a narrowing — it only tells {@link encryptCollectedTerms}
   * which capability to demand of the column. Getting it wrong therefore
   * produces a wrong accept/reject, not a wrong ciphertext: the base class's
   * `'equality'` default rejects `.filter('bio', 'cs', …)` on a
   * `public.eql_v3_text_match` column, the one query that column can answer.
   *
   * Unknown operators throw rather than silently defaulting to equality, which
   * would encrypt a term the column may not even be able to compare.
   */
  protected override queryTypeForRawOp(operator: string): QueryTypeName {
    switch (operator) {
      case 'cs':
        return 'freeTextSearch'
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte':
        return 'orderAndRange'
      case 'eq':
      case 'neq':
      case 'in':
      case 'is':
        return 'equality'
      default:
        throw new Error(
          `[supabase v3]: unsupported raw filter operator "${operator}" on an encrypted column`,
        )
    }
  }

  protected override buildSelectString(): DbSelect | null {
    if (this.selectColumns === null) return null
    return addJsonbCastsV3(this.selectColumns, this.propToDb)
  }

  /**
   * Expand the introspected column list (DB names) into JS property names.
   *
   * Load-bearing for `select('*')` on a DECLARED table that renames a column.
   * `addJsonbCastsV3` only emits the `prop:db_name::jsonb` alias — the thing
   * that makes PostgREST return the column under its property name — when the
   * token it sees is a property name. Feeding it the raw DB name instead takes
   * the unaliased `dbNames.has(...)` branch, so the row comes back keyed
   * `created_at` while the declared row type promises `createdAt`, silently
   * yielding `undefined` for a field TypeScript guarantees.
   *
   * A DB column with no encrypted builder (plaintext passthrough, and every
   * synthesized column, where property == DB name) maps to itself.
   */
  protected override expandAllColumns(columns: string[]): string[] {
    return columns.map((dbName) =>
      Object.hasOwn(this.dbToProp, dbName) ? this.dbToProp[dbName] : dbName,
    )
  }

  /** v3 domains are plain jsonb — send the raw payload, keyed by DB name. */
  protected override transformEncryptedMutationModel(
    model: Record<string, unknown>,
  ): Record<string, unknown> {
    const out: Record<string, unknown> = Object.create(null)
    for (const [key, value] of Object.entries(model)) {
      out[this.dbNameFor(key)] = value
    }
    return out
  }

  protected override transformEncryptedMutationModels(
    models: Record<string, unknown>[],
  ): Record<string, unknown>[] {
    return models.map((model) => this.transformEncryptedMutationModel(model))
  }

  /**
   * Validate a term's query type against its column's declared capabilities.
   * Pure validation: `encrypt`/`bulkEncrypt` never receive the query type — the
   * v3 filter operand is a full storage envelope (see the class doc for why
   * `encryptQuery` terms cannot be used).
   */
  private assertTermQueryable(term: ScalarQueryTerm): V3ColumnLike {
    const column = term.column as unknown as V3ColumnLike
    const queryType = term.queryType ?? 'equality'

    if (
      queryType !== 'equality' &&
      queryType !== 'orderAndRange' &&
      queryType !== 'freeTextSearch'
    ) {
      throw new Error(
        `[supabase v3]: query type "${queryType}" is not supported on scalar EQL v3 columns`,
      )
    }

    if (!column.getQueryCapabilities()[queryType]) {
      throw new Error(
        `[supabase v3]: column "${column.getName()}" (${column.getEqlType()}) does not support ${queryType} queries — declare the column with a domain that carries that capability`,
      )
    }

    return column
  }

  private encryptionFailure(message: string, cause?: unknown): never {
    logger.error(
      `Supabase: failed to encrypt query terms for table "${this.tableName}"`,
    )
    throw new EncryptionFailedError(
      `Failed to encrypt query terms: ${message}`,
      cause,
    )
  }

  /**
   * Encrypt every filter operand as a full storage envelope, serialized to jsonb
   * text for the PostgREST filter value.
   *
   * Terms are grouped by column and each group takes ONE `bulkEncrypt` crossing.
   * `in(col, [a, b, c])` collects one term per element (the list must never be
   * encrypted whole), so encrypting per term spent N ZeroKMS/FFI round-trips
   * where one would do. `bulkEncrypt` carries a single `{table, column}` for the
   * whole payload, so the grouping is mandatory, not an optimisation: one bulk
   * call over a mixed-column term array would stamp one column onto every
   * plaintext. Results are scattered back onto the terms' original indices,
   * which is the contract `termMap` downstream relies on.
   *
   * Mirrors `eql/v3/drizzle/operators.ts` `encryptOperands` — same batching
   * contract, same length assertion, same fallback. Kept separate because that
   * one encrypts a single-column operand list and returns `SQL[]`, while this
   * must group a multi-column term array and preserve positions.
   */
  protected override async encryptCollectedTerms(
    terms: ScalarQueryTerm[],
  ): Promise<unknown[]> {
    const groups = new Map<
      V3ColumnLike,
      { indices: number[]; values: ScalarQueryTerm['value'][] }
    >()
    terms.forEach((term, index) => {
      const column = this.assertTermQueryable(term)
      const group = groups.get(column) ?? { indices: [], values: [] }
      group.indices.push(index)
      group.values.push(term.value)
      groups.set(column, group)
    })

    const bulkEncrypt = this.encryptionClient.bulkEncrypt?.bind(
      this.encryptionClient,
    )
    const results = new Array<unknown>(terms.length)

    await Promise.all(
      Array.from(groups, async ([column, { indices, values }]) => {
        const encrypted = bulkEncrypt
          ? await this.bulkEncryptGroup(bulkEncrypt, column, values)
          : await this.encryptGroupPerTerm(column, values)

        encrypted.forEach((envelope, i) => {
          results[indices[i]] = JSON.stringify(envelope)
        })
      }),
    )

    return results
  }

  /** One FFI crossing for a column's whole operand list. */
  private async bulkEncryptGroup(
    bulkEncrypt: NonNullable<EncryptionClient['bulkEncrypt']>,
    column: V3ColumnLike,
    values: ScalarQueryTerm['value'][],
  ): Promise<unknown[]> {
    const baseOp = bulkEncrypt(
      values.map((plaintext) => ({ plaintext })) as never,
      { column, table: this.v3Table } as never,
    )
    const op = this.lockContext
      ? baseOp.withLockContext(this.lockContext)
      : baseOp
    if (this.auditConfig) op.audit(this.auditConfig)

    const result = await op
    if (result.failure)
      this.encryptionFailure(result.failure.message, result.failure)

    // `bulkEncrypt` is position-stable, so a length mismatch means the contract
    // was violated. Truncating instead would silently widen an `in` predicate
    // (or narrow a `not.in`) to whatever came back.
    const encrypted = result.data as Array<{ data: unknown }> | undefined
    if (!Array.isArray(encrypted) || encrypted.length !== values.length) {
      this.encryptionFailure(
        `bulk encryption returned ${Array.isArray(encrypted) ? encrypted.length : 0} terms for ${values.length} values on column "${column.getName()}".`,
      )
    }
    return encrypted.map((term) => term.data)
  }

  /** Fallback for a client that predates `bulkEncrypt`. */
  private async encryptGroupPerTerm(
    column: V3ColumnLike,
    values: ScalarQueryTerm['value'][],
  ): Promise<unknown[]> {
    return Promise.all(
      values.map(async (value) => {
        const baseOp = this.encryptionClient.encrypt(value, {
          column,
          table: this.v3Table,
        })
        const op = this.lockContext
          ? baseOp.withLockContext(this.lockContext)
          : baseOp
        if (this.auditConfig) op.audit(this.auditConfig)

        const result = await op
        if (result.failure) {
          this.encryptionFailure(result.failure.message, result.failure)
        }
        return result.data
      }),
    )
  }

  /**
   * `like`/`ilike` do not exist on the v3 surface (see the class doc). The
   * typed builder omits them, but an untyped JS caller can still reach them —
   * refuse loudly rather than emit a `~~` the domain has no operator for.
   *
   * A plaintext column is a genuine PostgREST text column, so `like` there is
   * exactly what the caller means; let it through.
   */
  private assertNotEncryptedPattern(column: string, op: string): void {
    if (!this.v3Columns[column]) return
    throw new Error(
      `[supabase v3]: "${op}" is not supported on encrypted column "${column}" — EQL v3 free-text search is token containment, not SQL wildcard matching ("%" is tokenized like any other character). Use contains().`,
    )
  }

  override like(column: string, pattern: string): this {
    this.assertNotEncryptedPattern(column, 'like')
    return super.like(column, pattern)
  }

  override ilike(column: string, pattern: string): this {
    this.assertNotEncryptedPattern(column, 'ilike')
    return super.ilike(column, pattern)
  }

  /**
   * Encrypted `contains` goes through the bloom-filter `@>`, which the bundle
   * declares on the domain as PostgREST's `cs`. The operand is the full storage
   * envelope; `eql_v3.contains` extracts the `bf` array from both sides.
   *
   * Emitted via `filter(col, 'cs', json)` rather than `q.contains(col, json)`:
   * postgrest-js's `contains` re-serializes a non-string operand, and our
   * operand is already `JSON.stringify`d.
   */
  protected override applyContainsFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    value: unknown,
    wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    if (wasEncrypted) {
      return q.filter(column, 'cs', value)
    }
    return super.applyContainsFilter(q, column, value, wasEncrypted)
  }

  /**
   * `.or()` string conditions carry raw PostgREST operators, so a free-text
   * condition arrives as `cs` — not a {@link FilterOp}. Resolve it through the
   * same table the raw `.filter()` path uses, so `.or('amount.cs.5')` on an
   * `integer_ord` column is rejected by the capability guard rather than
   * silently encrypted as an equality term.
   */
  protected override queryTypeForOrOp(op: FilterOp): QueryTypeName {
    if (op === 'contains') return 'freeTextSearch'
    return this.queryTypeForRawOp(op)
  }

  /** Rebuild `Date` values from the encrypt-config `cast_as` (date/timestamp),
   * mirroring the typed v3 client's decrypt-model path. */
  protected override postprocessDecryptedRow(
    row: Record<string, unknown>,
  ): Record<string, unknown> {
    // Every key an encrypted column can appear under: the keys this select
    // actually produces (including caller-chosen aliases like `ts:createdAt`),
    // plus the static property and DB names as a fallback for paths that record
    // no select. Aliases win. Derived here from `this.selectColumns` (the row in
    // hand) rather than cached from `buildSelectString`, so a reused builder can
    // never postprocess a row with a previous operation's stale select map.
    const keyToDb: Record<string, string> = Object.assign(
      Object.create(null),
      this.selectColumns === null
        ? undefined
        : selectKeyToDbV3(this.selectColumns, this.propToDb),
    )
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      keyToDb[property] ??= dbName
      keyToDb[dbName] ??= dbName
    }

    const out: Record<string, unknown> = { ...row }
    for (const [key, dbName] of Object.entries(keyToDb)) {
      const castAs = this.columnSchemas[dbName]?.cast_as
      if (!DATE_LIKE_CAST_SET.has(castAs as string)) continue
      const value = out[key]
      if (value == null || value instanceof Date) continue
      if (typeof value === 'string' || typeof value === 'number') {
        out[key] = new Date(value)
      }
    }
    return out
  }
}
