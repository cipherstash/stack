import { Column, is, type SQL, sql } from 'drizzle-orm'
import { type IndexBuilder, index } from 'drizzle-orm/pg-core'
import { getEqlV3Column } from './column.js'
import { getDrizzleTableName } from './schema-extraction.js'
import { EQL_V3_FN_SCHEMA } from './sql-dialect.js'

/**
 * Derive the recommended functional indexes for every encrypted column in a
 * table, from the same per-domain capability record the operator layer gates
 * on (`builder.build().indexes`) — so the emitted indexes and the operators
 * that engage them cannot drift.
 *
 * Call it inside `pgTable`'s third-argument callback and spread the result:
 *
 * ```ts
 * export const users = pgTable(
 *   'users',
 *   {
 *     id: integer('id').primaryKey(),
 *     email: types.TextEq('email'),
 *     bio: types.TextSearch('bio'),
 *   },
 *   (t) => [...encryptedIndexes(t)],
 * )
 * ```
 *
 * Emitted per capability, named `<table>_<column>_<capability>`:
 *
 * - equality (`hm` term)   → `USING btree (eql_v3.eq_term(col))`
 * - ordering (`op` term)   → `USING btree (eql_v3.ord_term(col))`
 * - ORE ordering (`ob`)    → `USING btree (eql_v3.ord_term_ore(col))`
 * - free-text match (`bf`) → `USING gin (eql_v3.match_term(col))`
 * - encrypted JSON         → `USING gin ((eql_v3.to_ste_vec_query(col)::jsonb) jsonb_path_ops)`
 *
 * A `text_search` column therefore yields three indexes; an `_ord` /
 * `_ord_ore` column yields ONE — the bundle defines no `eq_term` overload for
 * those domains (`eql_v3.eq` inlines to an ordering-term comparison), so the
 * single ordering btree serves `=` and range alike. A storage-only column
 * (bare `types.T`, `types.Boolean`) yields none — it carries no term.
 * Non-encrypted columns are ignored. Field-level selector indexes on
 * encrypted JSON cannot be derived here (the selector hash is data the
 * crypto layer emits, not schema) — declare those by hand; see the
 * `stash-indexing` skill for the recipe.
 *
 * Existing tables adopt these through a normal `drizzle-kit generate`
 * migration; run `ANALYZE <table>` after it applies — an expression index
 * gathers no statistics at `CREATE INDEX` time. The gap this closes (#753):
 * the integration emitted operators but no index DDL, so encrypted
 * predicates sequential-scanned by default.
 */
export function encryptedIndexes(
  columns: Record<string, unknown>,
): IndexBuilder[] {
  const builders: IndexBuilder[] = []
  for (const [property, column] of Object.entries(columns)) {
    if (!is(column, Column)) continue
    const dbName = typeof column.name === 'string' ? column.name : property
    const eqlColumn = getEqlV3Column(dbName, column)
    if (!eqlColumn) continue

    const base = `${tableNameOf(column)}_${dbName}`
    const indexes = eqlColumn.build().indexes
    if (indexes.unique) {
      builders.push(
        index(`${base}_eq`).using('btree', extractor('eq_term', column)),
      )
    }
    if (indexes.ope) {
      builders.push(
        index(`${base}_ord`).using('btree', extractor('ord_term', column)),
      )
    }
    if (indexes.ore) {
      builders.push(
        index(`${base}_ord_ore`).using(
          'btree',
          extractor('ord_term_ore', column),
        ),
      )
    }
    if (indexes.match) {
      builders.push(
        index(`${base}_match`).using('gin', extractor('match_term', column)),
      )
    }
    if (indexes.ste_vec) {
      // GIN over the ste_vec query shape; the opclass rides inside the
      // expression because `.op()` exists only for plain column elements.
      builders.push(
        index(`${base}_json`).using(
          'gin',
          sql`(${extractor('to_ste_vec_query', column)}::jsonb) jsonb_path_ops`,
        ),
      )
    }
  }
  return builders
}

/** `eql_v3.<fn>(col)` — the functional-index expression the planner's inlined
 *  operators match structurally (same `EQL_V3_FN_SCHEMA` as the dialect). */
function extractor(fn: string, column: Column): SQL {
  return sql`${sql.raw(`${EQL_V3_FN_SCHEMA}.${fn}`)}(${column})`
}

/**
 * Index names must be unique per Postgres schema, so they are prefixed with
 * the table name — read off the column's owning table, which exists exactly
 * when the helper runs where it belongs: inside the `pgTable` callback.
 */
function tableNameOf(column: Column): string {
  const name = getDrizzleTableName((column as { table?: unknown }).table)
  if (!name) {
    throw new Error(
      "[stack-drizzle]: encryptedIndexes could not read the column's table " +
        "name. Call it inside pgTable's third-argument callback: " +
        'pgTable(name, columns, (t) => [...encryptedIndexes(t)]).',
    )
  }
  return name
}
