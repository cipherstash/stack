/**
 * Shared scaffolding for the live-PG EQL v3 suites.
 *
 * Everything on the encryption path is REAL:
 *
 *   - the client is `cipherstashFromStackV3({ contractJson })` over a
 *     real `EncryptionV3` (ZeroKMS round-trips, no fakes);
 *   - writes go through the REAL v3 bulk-encrypt middleware returned by
 *     that factory (`cs.middleware[0].beforeExecute`), driven exactly
 *     the way the SQL runtime drives it: an execution plan whose AST
 *     carries the `ParamRef`s, plus `createSqlParamRefMutator(plan)`;
 *   - reads decrypt through the same per-castAs envelope
 *     `fromInternal(...).decrypt()` path the v3 cell codec's `decode`
 *     uses, against a `createCipherstashV3Sdk` adapter over the same
 *     client;
 *   - operator SELECTs are lowered by the REAL postgres adapter from
 *     the REAL v3 operator descriptors (`makeV3Adapter().lower`), so
 *     the SQL that executes against Postgres is byte-for-byte the SQL
 *     the product emits.
 *
 * Only the plumbing a full ORM client would add (driver wiring, model
 * accessors) is inlined — same seams as the unit-level middleware and
 * operator-lowering suites, now pointed at a real database.
 */

import type { PostgresContract } from '@prisma-next/adapter-postgres/types'
import { validateSqlContractFully } from '@prisma-next/sql-contract/validators'
import {
  type AnyExpression,
  ColumnRef,
  InsertAst,
  type OrderByItem,
  ParamRef,
  ProjectionItem,
  SelectAst,
  TableSource,
} from '@prisma-next/sql-relational-core/ast'
import type { SqlExecutionPlan } from '@prisma-next/sql-relational-core/plan'
import type { SqlMiddleware } from '@prisma-next/sql-runtime'
import postgres from 'postgres'
import type { EncryptedEnvelopeBase } from '../../../src/execution/envelope-base'
import type { CipherstashSdk } from '../../../src/execution/sdk'
import {
  type CipherstashFromStackV3Result,
  cipherstashFromStackV3,
} from '../../../src/stack/from-stack-v3'
import {
  toV3CodecId,
  V3_DOMAIN_META_BY_CODEC_ID,
} from '../../../src/v3/catalog'
import { deriveStackSchemasV3 } from '../../../src/v3/derive-schemas-v3'
import { createCipherstashV3Sdk } from '../../../src/v3/sdk-adapter-v3'
import { v3FromDriver } from '../../../src/v3/wire-v3'
import {
  baseMeta,
  createCtx,
  createSqlParamRefMutator,
} from '../../bulk-encrypt-middleware.helpers'
import {
  literalParamValue,
  makeV3Adapter,
} from '../../v3/operator-lowering-v3.helpers'
import { liveDatabaseUrl } from './live-gate'

// GA codec ids (registry key VERBATIM — never strip the `eql_v3_` prefix).
export const TEXT_SEARCH = toV3CodecId('eql_v3_text_search')
export const TEXT_EQ = toV3CodecId('eql_v3_text_eq')
export const INTEGER_ORD = toV3CodecId('eql_v3_integer_ord')
export const DATE_ORD = toV3CodecId('eql_v3_date_ord')
export const TIMESTAMP_ORD = toV3CodecId('eql_v3_timestamp_ord')
export const BOOLEAN = toV3CodecId('eql_v3_boolean')
export const BIGINT_STORAGE = toV3CodecId('eql_v3_bigint')
export const BIGINT_EQ = toV3CodecId('eql_v3_bigint_eq')
export const BIGINT_ORD = toV3CodecId('eql_v3_bigint_ord')
export const JSON_CODEC = toV3CodecId('eql_v3_json')

const PG_TEXT = 'pg/text@1'

/**
 * A live connection with the settings every suite wants: no prepared
 * statements (poolers), and `DROP TABLE IF EXISTS` notices silenced so
 * the vitest output stays readable.
 */
export function liveConnection(): postgres.Sql {
  return postgres(liveDatabaseUrl(), { prepare: false, onnotice: () => {} })
}

export function domainFor(codecId: string): string {
  const meta = V3_DOMAIN_META_BY_CODEC_ID.get(codecId)
  if (!meta) throw new Error(`live harness: unknown v3 codec id ${codecId}`)
  return meta.nativeType
}

/**
 * Build a validated contract for one live table: a plain-text `id`
 * primary key plus one v3 column per `(name → codec id)` entry, each
 * carrying its concrete `public.eql_v3_*` domain and the catalog's
 * `{ castAs, capabilities }` typeParams block — the exact shape v3
 * authoring emits.
 */
export function liveV3Contract(
  tableName: string,
  columns: Readonly<Record<string, string>>,
): PostgresContract {
  const columnEntries: Record<string, object> = {
    id: { codecId: PG_TEXT, nativeType: 'text', nullable: false },
  }
  for (const [name, codecId] of Object.entries(columns)) {
    const meta = V3_DOMAIN_META_BY_CODEC_ID.get(codecId)
    if (!meta) throw new Error(`live harness: unknown v3 codec id ${codecId}`)
    columnEntries[name] = {
      codecId,
      nativeType: meta.nativeType,
      nullable: true,
      typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
    }
  }
  return validateSqlContractFully<PostgresContract>({
    target: 'postgres',
    targetFamily: 'sql',
    profileHash: `sha256:cipherstash-live-${tableName}`,
    roots: {},
    capabilities: {},
    extensionPacks: {},
    meta: {},
    storage: {
      storageHash: `sha256:cipherstash-live-${tableName}-storage`,
      namespaces: {
        __unbound__: {
          id: '__unbound__',
          entries: {
            table: {
              [tableName]: {
                columns: columnEntries,
                uniques: [],
                indexes: [],
                foreignKeys: [],
              },
            },
          },
        },
      },
    },
    domain: { namespaces: { __unbound__: { models: {} } } },
  })
}

/** DROP + CREATE the live table matching a `liveV3Contract` fixture. */
export async function createLiveTable(
  sql: postgres.Sql,
  tableName: string,
  columns: Readonly<Record<string, string>>,
): Promise<void> {
  const defs = Object.entries(columns)
    .map(([name, codecId]) => `"${name}" ${domainFor(codecId)}`)
    .join(', ')
  await sql.unsafe(`DROP TABLE IF EXISTS "${tableName}"`)
  await sql.unsafe(
    `CREATE TABLE "${tableName}" (id text PRIMARY KEY${defs ? `, ${defs}` : ''})`,
  )
}

export interface LiveV3Client {
  readonly cs: CipherstashFromStackV3Result
  /** The REAL middleware instance wired by `cipherstashFromStackV3`. */
  readonly middleware: SqlMiddleware
  /** Read-side SDK adapter over the same client (envelope decrypt path). */
  readonly sdk: CipherstashSdk
}

export async function setupLiveV3(
  contract: PostgresContract,
): Promise<LiveV3Client> {
  const cs = await cipherstashFromStackV3({ contractJson: contract })
  const middleware = cs.middleware[0]
  if (!middleware) {
    throw new Error('cipherstashFromStackV3 returned no middleware')
  }
  const sdk = createCipherstashV3Sdk(
    cs.encryptionClient,
    deriveStackSchemasV3(contract),
  )
  return { cs, middleware, sdk }
}

export interface LiveRowSpec {
  readonly id: string
  /** column name → { codecId, value } (value: plaintext envelope or null). */
  readonly cells: Readonly<
    Record<string, { readonly codecId: string; readonly value: unknown }>
  >
}

/**
 * INSERT rows through the REAL v3 bulk-encrypt middleware: build the
 * `InsertAst` + hand-written INSERT statement with positionally-matching
 * params, run `beforeExecute` (which stamps routing keys from the AST,
 * batches per-column `bulkEncrypt`/`encryptQuery` crossings, and
 * replaces envelope params with JSONB text), then execute against the
 * live database.
 *
 * Every row's params are bound in the FIRST row's column order (the
 * canonical `cellColumns` list below): the INSERT column list is built
 * once from the first row, so a later row iterated in its own
 * `Object.entries` order could silently bind values to the wrong SQL
 * columns. A row with a differing column set throws instead.
 */
export async function insertEncryptedRows(
  sql: postgres.Sql,
  middleware: SqlMiddleware,
  tableName: string,
  rows: ReadonlyArray<LiveRowSpec>,
): Promise<void> {
  const first = rows[0]
  if (!first) return
  const cellColumns = Object.keys(first.cells)
  const columnNames = ['id', ...cellColumns]

  const params: unknown[] = []
  const astRows = rows.map((row) => {
    const rowColumns = Object.keys(row.cells)
    if (
      rowColumns.length !== cellColumns.length ||
      !cellColumns.every((column) => column in row.cells)
    ) {
      throw new Error(
        `insertEncryptedRows: row "${row.id}" columns [${rowColumns.join(
          ', ',
        )}] do not match the first row's [${cellColumns.join(', ')}]`,
      )
    }
    const astRow: Record<string, ParamRef> = {}
    const idRef = ParamRef.of(row.id, { codec: { codecId: PG_TEXT } })
    astRow.id = idRef
    params.push(row.id)
    for (const column of cellColumns) {
      const cell = row.cells[column]
      if (!cell) {
        throw new Error(
          `insertEncryptedRows: row "${row.id}" is missing column "${column}"`,
        )
      }
      const ref = ParamRef.of(cell.value, {
        codec: { codecId: cell.codecId },
      })
      astRow[column] = ref
      params.push(cell.value)
    }
    return astRow
  })

  const placeholders = rows
    .map(
      (_, rowIndex) =>
        `(${columnNames
          .map(
            (_c, colIndex) =>
              `$${rowIndex * columnNames.length + colIndex + 1}`,
          )
          .join(', ')})`,
    )
    .join(', ')
  const insertSql = `INSERT INTO "${tableName}" (${columnNames
    .map((c) => `"${c}"`)
    .join(', ')}) VALUES ${placeholders}`

  const ast = new InsertAst(TableSource.named(tableName), astRows)
  const plan = {
    sql: insertSql,
    params,
    meta: { ...baseMeta },
    ast,
  } as SqlExecutionPlan

  const mutator = createSqlParamRefMutator(plan)
  await middleware.beforeExecute?.(plan, createCtx(), mutator)
  // The middleware replaced every envelope param with plain JSONB text;
  // what remains is driver-serialisable.
  await sql.unsafe(insertSql, [...mutator.currentParams()] as never[])
}

/** `SELECT id FROM t WHERE <predicate>` as a SelectAst. */
export function selectIdsWhere(
  tableName: string,
  predicate: AnyExpression,
): SelectAst {
  return SelectAst.from(TableSource.named(tableName))
    .withProjection([ProjectionItem.of('id', ColumnRef.of(tableName, 'id'))])
    .withWhere(predicate)
}

/** `SELECT id FROM t ORDER BY <items>` as a SelectAst. */
export function selectIdsOrderBy(
  tableName: string,
  items: ReadonlyArray<OrderByItem>,
): SelectAst {
  return SelectAst.from(TableSource.named(tableName))
    .withProjection([ProjectionItem.of('id', ColumnRef.of(tableName, 'id'))])
    .withOrderBy(items)
}

export interface ExecutedSelect {
  readonly sql: string
  readonly ids: string[]
}

/**
 * Lower a SelectAst through the real postgres adapter + v3 operator
 * descriptors, run the lowered params through the REAL middleware (this
 * is where operator query-term envelopes become ciphertext-free
 * `encryptQuery` terms), execute the lowered SQL against the live
 * database, and return the selected ids.
 */
export async function runLoweredSelect(
  sql: postgres.Sql,
  middleware: SqlMiddleware,
  contract: PostgresContract,
  ast: SelectAst,
): Promise<ExecutedSelect> {
  const lowered = makeV3Adapter().lower(ast, { contract })
  const plan = {
    sql: lowered.sql,
    params: lowered.params.map(literalParamValue),
    meta: { ...baseMeta },
    ast,
  } as SqlExecutionPlan
  const mutator = createSqlParamRefMutator(plan)
  await middleware.beforeExecute?.(plan, createCtx(), mutator)
  const rows = (await sql.unsafe(lowered.sql, [
    ...mutator.currentParams(),
  ] as never[])) as unknown as Array<{ id: string }>
  return { sql: lowered.sql, ids: rows.map((row) => row.id) }
}

/**
 * Read one encrypted cell straight off the table and decrypt it through
 * the envelope path the v3 cell codec's `decode` uses.
 */
export async function selectCell(
  sql: postgres.Sql,
  tableName: string,
  column: string,
  id: string,
): Promise<unknown> {
  const rows = (await sql.unsafe(
    `SELECT "${column}" AS cell FROM "${tableName}" WHERE id = $1`,
    [id],
  )) as unknown as Array<{ cell: unknown }>
  if (rows.length !== 1) {
    throw new Error(
      `selectCell: expected exactly 1 row for ${tableName}.${column} id=${id}, got ${rows.length}`,
    )
  }
  return rows[0]?.cell
}

export async function decryptCell<T>(
  sdk: CipherstashSdk,
  envelope: {
    fromInternal(args: {
      ciphertext: unknown
      table: string
      column: string
      sdk: CipherstashSdk
    }): EncryptedEnvelopeBase<T>
  },
  args: {
    readonly cell: unknown
    readonly table: string
    readonly column: string
  },
): Promise<T> {
  return envelope
    .fromInternal({
      ciphertext: v3FromDriver(args.cell as string | object | null),
      table: args.table,
      column: args.column,
      sdk,
    })
    .decrypt()
}
