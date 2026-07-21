/**
 * Shared harness for the bulk-encrypt middleware suite
 * (`v3/bulk-encrypt-v3.test.ts`) and the live-PG harness. Plan builders
 * take the codec id to stamp on each `ParamRef` (defaulting to a
 * searchable v3 text domain; callers that need a specific domain pass
 * their own), and the mock SDK echoes whatever ciphertext shape the
 * caller's `encryptImpl` produces.
 */

import type { Contract, PlanMeta } from '@prisma-next/contract/types'
import type { SqlStorage } from '@prisma-next/sql-contract/types'
import {
  type ColumnRef,
  InsertAst,
  ParamRef,
  TableSource,
  UpdateAst,
} from '@prisma-next/sql-relational-core/ast'
import type { SqlExecutionPlan } from '@prisma-next/sql-relational-core/plan'
import type { SqlMiddlewareContext } from '@prisma-next/sql-runtime'
import { vi } from 'vitest'
import type {
  CipherstashBulkDecryptArgs,
  CipherstashBulkEncryptArgs,
  CipherstashSdk,
  CipherstashSingleDecryptArgs,
} from '../src/execution/sdk'

// Default codec id for the plan-builder helpers below (callers that need a
// specific domain pass their own). A searchable v3 text domain.
const DEFAULT_CODEC_ID = 'cipherstash/eql-v3/eql_v3_text_search@1'

export { createSqlParamRefMutator } from '@prisma-next/sql-relational-core/middleware'

export const baseMeta: PlanMeta = {
  target: 'postgres',
  storageHash: 'sha256:test',
  lane: 'dsl',
}

export function createCtx(
  overrides?: Partial<SqlMiddlewareContext>,
): SqlMiddlewareContext {
  return {
    contract: {} as Contract<SqlStorage>,
    mode: 'strict' as const,
    scope: 'runtime' as const,
    now: () => Date.now(),
    log: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    contentHash: async () => 'mock-hash',
    planExecutionId: 'test-plan-execution',
    ...overrides,
  }
}

export interface CounterSdk extends CipherstashSdk {
  readonly bulkEncryptCalls: CipherstashBulkEncryptArgs[]
  readonly bulkDecryptCalls: CipherstashBulkDecryptArgs[]
  readonly singleDecryptCalls: CipherstashSingleDecryptArgs[]
}

export function makeCounterSdk(options?: {
  encryptImpl?: (args: CipherstashBulkEncryptArgs) => ReadonlyArray<unknown>
}): CounterSdk {
  const bulkEncryptCalls: CipherstashBulkEncryptArgs[] = []
  const bulkDecryptCalls: CipherstashBulkDecryptArgs[] = []
  const singleDecryptCalls: CipherstashSingleDecryptArgs[] = []
  const encryptImpl =
    options?.encryptImpl ??
    ((args: CipherstashBulkEncryptArgs) =>
      args.values.map(
        (plaintext) =>
          `cipher:${args.routingKey.table}.${args.routingKey.column}:${plaintext}`,
      ))
  return {
    bulkEncryptCalls,
    bulkDecryptCalls,
    singleDecryptCalls,
    decrypt(args) {
      singleDecryptCalls.push(args)
      return Promise.resolve(`single:${String(args.ciphertext)}`)
    },
    bulkEncrypt(args) {
      bulkEncryptCalls.push(args)
      return Promise.resolve(encryptImpl(args))
    },
    bulkDecrypt(args) {
      bulkDecryptCalls.push(args)
      return Promise.resolve(
        args.ciphertexts.map((c) => `bulk-decrypt:${String(c)}`),
      )
    },
  }
}

export function buildInsertPlan(
  table: string,
  rows: ReadonlyArray<Record<string, unknown>>,
  codecId: string = DEFAULT_CODEC_ID,
): SqlExecutionPlan {
  const params: unknown[] = []
  const astRows = rows.map((row) => {
    const out: Record<string, ParamRef> = {}
    for (const [column, value] of Object.entries(row)) {
      const ref = ParamRef.of(value, {
        codec: { codecId },
      })
      out[column] = ref
      params.push(value)
    }
    return out
  })
  const ast = new InsertAst(TableSource.named(table), astRows)
  return {
    sql: `INSERT INTO "${table}" (...) VALUES (...)`,
    params,
    meta: { ...baseMeta },
    ast,
  } as SqlExecutionPlan
}

export function buildUpdatePlan(
  table: string,
  set: Record<string, unknown>,
  codecId: string = DEFAULT_CODEC_ID,
): SqlExecutionPlan {
  const params: unknown[] = []
  const astSet: Record<string, ParamRef | ColumnRef> = {}
  for (const [column, value] of Object.entries(set)) {
    const ref = ParamRef.of(value, {
      codec: { codecId },
    })
    astSet[column] = ref
    params.push(value)
  }
  const ast = new UpdateAst(TableSource.named(table), astSet)
  return {
    sql: `UPDATE "${table}" SET ...`,
    params,
    meta: { ...baseMeta },
    ast,
  } as SqlExecutionPlan
}
