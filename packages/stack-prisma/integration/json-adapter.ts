import { stripDomainSchema } from '@cipherstash/stack/adapter-kit'
import {
  databaseUrl,
  type JsonIntegrationAdapter,
  type JsonQueryOp,
  type JsonTableSpec,
} from '@cipherstash/test-kit'
import type {
  AnyExpression,
  SelectAst,
} from '@prisma-next/sql-relational-core/ast'
import { ColumnRef, OrderByItem } from '@prisma-next/sql-relational-core/ast'
import postgres from 'postgres'
import { EncryptedJson } from '../src/execution/envelope-json'
import { toV3CodecId } from '../src/v3/catalog'
import { eqlJsonPathAsc, eqlJsonPathDesc } from '../src/v3/operators-v3'
import {
  createLiveTable,
  insertEncryptedRows,
  JSON_CODEC,
  type LiveV3Client,
  liveV3Contract,
  runLoweredSelect,
  selectIdsOrderBy,
  selectIdsWhere,
  setupLiveV3,
} from '../test/live/helpers/harness'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../test/v3/operator-lowering-v3.helpers'

const SELECTOR_METHOD = {
  eq: 'eqlJsonPathEq',
  ne: 'eqlJsonPathNeq',
  gt: 'eqlJsonPathGt',
  gte: 'eqlJsonPathGte',
  lt: 'eqlJsonPathLt',
  lte: 'eqlJsonPathLte',
} as const

/** Prisma Next implementation of the shared live encrypted-JSON contract. */
export function makePrismaNextJsonAdapter(): JsonIntegrationAdapter {
  let sql: postgres.Sql
  let tableName: string
  let live: LiveV3Client
  let contract: ReturnType<typeof liveV3Contract>
  const codecId = toV3CodecId(stripDomainSchema('public.eql_v3_json_search'))

  const accessor = () => columnAccessorV3(tableName, 'document', codecId)

  const predicateFor = (
    op: Exclude<JsonQueryOp, { kind: 'selectorOrder' }>,
  ) => {
    if (op.kind === 'contains') {
      return callOperator(getOperator('eqlJsonContains'), accessor(), op.value)
    }
    return callOperator(
      getOperator(SELECTOR_METHOD[op.comparison]),
      accessor(),
      op.path,
      op.value,
    )
  }

  return {
    name: 'prisma-next',

    async setup(spec: JsonTableSpec) {
      tableName = spec.name
      sql = postgres(databaseUrl(), { prepare: false, onnotice: () => {} })
      await createLiveTable(sql, tableName, { document: JSON_CODEC })
      contract = liveV3Contract(tableName, { document: JSON_CODEC })
      live = await setupLiveV3(contract)
      await insertEncryptedRows(
        sql,
        live.middleware,
        tableName,
        spec.rows.map((row) => ({
          id: row.rowKey,
          cells: {
            document: {
              codecId: JSON_CODEC,
              value: EncryptedJson.from(row.document),
            },
          },
        })),
      )
    },

    async teardown() {
      if (tableName) await sql.unsafe(`DROP TABLE IF EXISTS "${tableName}"`)
      await sql.end()
    },

    async run(op: JsonQueryOp): Promise<string[]> {
      let ast: SelectAst
      if (op.kind === 'selectorOrder') {
        const term =
          op.direction === 'asc'
            ? eqlJsonPathAsc(accessor(), op.path)
            : eqlJsonPathDesc(accessor(), op.path)
        ast = selectIdsOrderBy(tableName, [
          term,
          OrderByItem.asc(ColumnRef.of(tableName, 'id')),
        ])
      } else {
        ast = selectIdsWhere(tableName, predicateFor(op) as AnyExpression)
      }

      const { ids } = await runLoweredSelect(
        sql,
        live.middleware,
        contract,
        ast,
      )
      return ids
    },
  }
}
