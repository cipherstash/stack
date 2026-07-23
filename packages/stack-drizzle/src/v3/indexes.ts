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
 * import { integer, pgTable } from 'drizzle-orm/pg-core'
 * import { encryptedIndexes, types } from '@cipherstash/stack-drizzle/v3'
 *
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
 * A `types.TextSearch` column therefore yields three indexes. Ordering
 * columns differ by type: a numeric, date, or timestamp `*Ord` / `*OrdOre`
 * column yields a single ordering index that also serves `=` (EQL compares
 * those columns by their ordering term directly), while `types.TextOrd` /
 * `TextOrdOre` yield an equality index alongside the ordering one (text
 * equality runs on a separate term). A storage-only column (bare
 * `types.Text`, `types.Boolean`, …) yields none — it has no queryable term —
 * and non-encrypted columns are ignored. Field-level selector indexes on
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

/**
 * Build the SQL expression each index is defined over: the EQL term extractor
 * applied to the column — e.g. `extractor('eq_term', users.email)` renders
 * `eql_v3.eq_term("users"."email")`. Encrypted predicates compile to
 * comparisons on these same expressions, which is what makes the index
 * match. (Same `EQL_V3_FN_SCHEMA` as the query dialect.)
 */
function extractor(fn: string, column: Column): SQL {
  return sql`${sql.raw(`${EQL_V3_FN_SCHEMA}.${fn}`)}(${column})`
}

/**
 * Read the name of the table a column belongs to — e.g. the `email` column
 * of `pgTable('users', …)` gives `'users'`, so its indexes are named
 * `users_email_eq`, `users_email_ord`, … (index names must be unique per
 * Postgres schema, hence the table prefix). The owning table is set exactly
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
