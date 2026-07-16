import type { QueryOp, QueryOpKind } from './ops.ts'
import type { PlainRow, TableSpec } from './rows.ts'

/**
 * The seam between the shared driver and one adapter under test.
 *
 * The driver decides WHAT to assert — derived from the domain's capabilities —
 * and the adapter decides HOW to express it. Keeping the adapters behind one
 * interface is what stops Drizzle and Supabase from quietly covering different
 * operations while both suites read as "comprehensive".
 */
export interface IntegrationAdapter {
  readonly name: 'drizzle' | 'supabase' | 'wasm'

  /**
   * Operations this adapter can express at all, independent of any domain. Both
   * adapters currently cover the full `QueryOpKind` union, `order` included:
   * Drizzle emits `ORDER BY eql_v3.ord_term(col)`, and Supabase emits the jsonb
   * path `col->op`, which selects the same order-preserving OPE term. (Ordering
   * columns that lack an `ope` term are rejected by the capability matrix, not
   * by this set.)
   */
  readonly supportedOps: ReadonlySet<QueryOpKind>

  /**
   * Operations this adapter refuses on ANY encrypted column, regardless of its
   * capabilities — the half of the contract the capability matrix cannot derive.
   * Both adapters currently leave this empty: Supabase's one former entry,
   * `order`, is now allowed on OPE columns and rejected on ORE/none by the
   * ordering-flavour guard, which the capability matrix already drives. Kept as
   * the seam for a future adapter with a genuinely unconditional refusal.
   */
  readonly alwaysRejectedOps: ReadonlySet<QueryOpKind>

  /**
   * Whether the adapter has a SECOND, distinct code path for `in`-lists that the
   * driver should exercise alongside the primary one.
   *
   * Supabase does: `.in()` and the raw `.filter(col, 'in', […])` are different
   * code paths, and the raw one encrypted the whole list as a single term until
   * recently. Drizzle has one `inArray`, so running the variant there would add
   * a duplicate test under a name (`filter(in)`) that means nothing to it.
   */
  readonly hasRawInListPath?: boolean

  setup(): Promise<void>
  teardown(): Promise<void>

  /** Create the table: one column per family domain, every encrypted column NULLable. */
  createTable(table: TableSpec): Promise<void>

  /** Insert one row through the adapter's single-encrypt path (`encryptModel`). */
  insertSingle(table: TableSpec, row: PlainRow): Promise<void>

  /** Insert many rows through the adapter's bulk path (`bulkEncryptModels`). */
  insertBulk(table: TableSpec, rows: readonly PlainRow[]): Promise<void>

  /**
   * Run `op` and return the matching row keys.
   *
   * For `order`, return them in the order the database produced, and exclude
   * NULLs — the seed set contains one all-NULL row, and NULL ordering is a
   * property of the SQL dialect, not of the encrypted ordering term. Every
   * other kind returns keys sorted ascending, so the driver can compare sets
   * without caring about row order.
   */
  run(table: TableSpec, op: QueryOp): Promise<string[]>

  /**
   * Assert `op` is rejected. Each adapter owns its error shape —
   * `EncryptionOperatorError` for Drizzle, a `[supabase v3]` Error for
   * Supabase — so the driver stays adapter-agnostic. Always async: wrap a
   * synchronous throw.
   */
  expectRejected(table: TableSpec, op: QueryOp): Promise<void>
}
