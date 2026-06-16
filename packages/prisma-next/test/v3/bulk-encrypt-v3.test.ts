/**
 * Drives `bulkEncryptV3Middleware(sdk).beforeExecute(plan, ctx, params)` over a
 * hand-built plan + param mutator, asserting the storage-vs-search split.
 */
import type { Contract, PlanMeta } from '@prisma-next/contract/types'
import {
  type AnyExpression,
  ColumnRef,
  InsertAst,
  ParamRef,
  ProjectionItem,
  SelectAst,
  TableSource,
} from '@prisma-next/sql-relational-core/ast'
import { createSqlParamRefMutator } from '@prisma-next/sql-relational-core/middleware'
import type { SqlExecutionPlan } from '@prisma-next/sql-relational-core/plan'
import type { SqlStorage } from '@prisma-next/sql-contract/types'
import type { SqlMiddlewareContext } from '@prisma-next/sql-runtime'
import { describe, expect, it, vi } from 'vitest'
import { cipherstashQueryOperations } from '../../src/execution/operators'
import {
  EncryptedString,
  setHandleQueryType,
} from '../../src/execution/envelope-string'
import type { EncryptedEnvelopeBase } from '../../src/execution/envelope-base'
import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../../src/extension-metadata/constants'
import type { V3Index } from '../../src/v3/domain-map'
import { bulkEncryptV3Middleware } from '../../src/middleware/bulk-encrypt-v3'
import { makeFakeSdk } from './helpers/fake-sdk'

const ops = cipherstashQueryOperations()

// A v3 column accessor whose CodecRef carries the index, so the operator stamps
// routing + queryType on the envelope (the real search path).
function v3Column(table: string, column: string, index: V3Index) {
  const ref = ColumnRef.of(table, column)
  return {
    returnType: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, nullable: true },
    codec: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index } },
    buildAst: () => ref,
  }
}

// Build a SELECT plan whose WHERE carries a v3 search ParamRef produced by the
// real operator (envelope stamped with routing + queryType at lowering time).
function buildV3SearchPlan(table: string, column: string, index: V3Index, method: string, value: unknown) {
  const op = ops[method]
  if (!op) throw new Error(`no operator ${method}`)
  const impl = op.impl as unknown as (...a: unknown[]) => { buildAst(): AnyExpression }
  const predicate = impl(v3Column(table, column, index), value).buildAst()
  const env = (predicate as unknown as { args: ReadonlyArray<{ value: unknown }> }).args[0]!.value
  const ast = SelectAst.from(TableSource.named(table))
    .withProjection([ProjectionItem.of('id', ColumnRef.of(table, 'id'))])
    .withWhere(predicate)
  return {
    plan: { sql: 'SELECT ... WHERE ...', params: [env], meta: { ...baseMeta }, ast } as SqlExecutionPlan,
    env: env as EncryptedEnvelopeBase<unknown>,
  }
}

const baseMeta = { invariants: [], capabilities: {} } as unknown as PlanMeta

function createCtx(overrides?: Partial<SqlMiddlewareContext>): SqlMiddlewareContext {
  return {
    contract: {} as Contract<SqlStorage>,
    mode: 'strict' as const,
    scope: 'runtime' as const,
    now: () => 0,
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    contentHash: async () => 'mock-hash',
    ...overrides,
  }
}

// Build an INSERT plan whose rows carry v3-codec ParamRefs (storage path: the AST
// walk stamps routing; no queryType).
function buildV3InsertPlan(table: string, row: Record<string, unknown>): SqlExecutionPlan {
  const params: unknown[] = []
  const out: Record<string, ParamRef> = {}
  for (const [column, value] of Object.entries(row)) {
    const ref = ParamRef.of(value, { codec: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID } })
    out[column] = ref
    params.push(value)
  }
  const ast = new InsertAst(TableSource.named(table), [out])
  return { sql: `INSERT INTO "${table}" (...) VALUES (...)`, params, meta: { ...baseMeta }, ast } as SqlExecutionPlan
}

describe('bulkEncryptV3Middleware', () => {
  it('routes query-term params (queryType marker) to bulkEncryptQuery, NOT bulkEncrypt', async () => {
    const bulkEncryptQuery = vi.fn(makeFakeSdk().bulkEncryptQuery)
    const bulkEncrypt = vi.fn(makeFakeSdk().bulkEncrypt)
    const sdk = makeFakeSdk({ bulkEncryptQuery, bulkEncrypt })
    const { plan } = buildV3SearchPlan('user_v3', 'email', 'equality', 'cipherstashEq', 'alice')
    const params = createSqlParamRefMutator(plan)

    await bulkEncryptV3Middleware(sdk).beforeExecute?.(plan, createCtx(), params)

    expect(bulkEncryptQuery).toHaveBeenCalledOnce()
    expect(bulkEncrypt).not.toHaveBeenCalled()
    expect(bulkEncryptQuery.mock.calls[0]![0]).toMatchObject({
      routingKey: { table: 'user_v3', column: 'email' },
      queryType: 'equality',
      values: ['alice'],
    })
    const current = params.currentParams()[0] as string
    expect(typeof current).toBe('string')
    expect(current.startsWith('{')).toBe(true)
  })

  it('routes storage params (no queryType) to bulkEncrypt → plain-jsonb wire', async () => {
    const bulkEncryptQuery = vi.fn(makeFakeSdk().bulkEncryptQuery)
    const bulkEncrypt = vi.fn(makeFakeSdk().bulkEncrypt)
    const sdk = makeFakeSdk({ bulkEncryptQuery, bulkEncrypt })
    const plan = buildV3InsertPlan('user_v3', { email: EncryptedString.from('stored') })
    const params = createSqlParamRefMutator(plan)

    await bulkEncryptV3Middleware(sdk).beforeExecute?.(plan, createCtx(), params)

    expect(bulkEncrypt).toHaveBeenCalledOnce()
    expect(bulkEncryptQuery).not.toHaveBeenCalled()
    const current = params.currentParams()[0] as string
    expect(current.startsWith('{')).toBe(true)
  })

  it('ignores v2 params (cipherstash/string@1 left untouched)', async () => {
    const bulkEncrypt = vi.fn(makeFakeSdk().bulkEncrypt)
    const sdk = makeFakeSdk({ bulkEncrypt })
    // A v2-codec ParamRef: the v3 middleware filters CIPHERSTASH_V3_CODEC_ID_SET,
    // which excludes cipherstash/string@1, so it must not touch this.
    const v2env = EncryptedString.from('v2')
    const ref = ParamRef.of(v2env, { codec: { codecId: 'cipherstash/string@1' } })
    const ast = new InsertAst(TableSource.named('user'), [{ email: ref }])
    const plan = { sql: 'INSERT', params: [v2env], meta: { ...baseMeta }, ast } as SqlExecutionPlan
    const params = createSqlParamRefMutator(plan)

    await bulkEncryptV3Middleware(sdk).beforeExecute?.(plan, createCtx(), params)

    expect(bulkEncrypt).not.toHaveBeenCalled()
    // param slot is unchanged (still the envelope, not a wire string)
    expect(params.currentParams()[0]).toBe(v2env)
  })

  it('throws if a query group mixes queryTypes', async () => {
    // The operator mismatch guard prevents two different query-types on one
    // column upstream, so construct the defensive scenario directly: two rows on
    // the same (table,column) routing key, each envelope manually stamped with a
    // DIFFERENT queryType. The INSERT walk stamps the shared routing key.
    const sdk = makeFakeSdk()
    const a = EncryptedString.from('a')
    setHandleQueryType(a, 'equality')
    const b = EncryptedString.from('b')
    setHandleQueryType(b, 'orderAndRange')
    const ast = new InsertAst(TableSource.named('user_v3'), [
      { email: ParamRef.of(a, { codec: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID } }) },
      { email: ParamRef.of(b, { codec: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID } }) },
    ])
    const plan = { sql: 'INSERT', params: [a, b], meta: { ...baseMeta }, ast } as SqlExecutionPlan
    const params = createSqlParamRefMutator(plan)

    await expect(bulkEncryptV3Middleware(sdk).beforeExecute?.(plan, createCtx(), params)).rejects.toThrow(
      /mixes queryTypes/,
    )
  })

  it('forwards ctx.signal to the SDK calls', async () => {
    const seen: (AbortSignal | undefined)[] = []
    const sdk = makeFakeSdk({
      bulkEncryptQuery: async ({ signal, values }) => {
        seen.push(signal)
        return values.map(() => ({ v: 2, i: { t: 't', c: 'c' }, hm: 'h' }))
      },
    })
    const { plan } = buildV3SearchPlan('user_v3', 'email', 'equality', 'cipherstashEq', 'alice')
    const params = createSqlParamRefMutator(plan)
    const controller = new AbortController()

    await bulkEncryptV3Middleware(sdk).beforeExecute?.(plan, createCtx({ signal: controller.signal }), params)
    expect(seen[0]).toBe(controller.signal)
  })
})
