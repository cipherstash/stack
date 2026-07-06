import type { EncryptionClient } from '@/encryption'
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { LockContext } from '@/identity'
import { PrismaEncryptedColumnError, PrismaEncryptionError } from './errors'
import { type ModelTableMeta, reconstructRow } from './model-map'
import type { PrismaNamespaceLike } from './types'

/** Operations whose `args` carry writable model data. */
const DATA_ARGS: Record<string, ReadonlyArray<'data' | 'create' | 'update'>> = {
  create: ['data'],
  update: ['data'],
  updateMany: ['data'],
  updateManyAndReturn: ['data'],
  createMany: ['data'],
  createManyAndReturn: ['data'],
  upsert: ['create', 'update'],
}

/** Operations whose result is a row / array of rows to decrypt. */
const ROW_RESULT_OPS = new Set([
  'create',
  'update',
  'upsert',
  'delete',
  'findMany',
  'findFirst',
  'findUnique',
  'findFirstOrThrow',
  'findUniqueOrThrow',
  'createManyAndReturn',
  'updateManyAndReturn',
])

/** Clauses of Prisma's TYPED query surface an encrypted column must not enter. */
const GUARDED_CLAUSES = ['where', 'orderBy', 'distinct', 'cursor', 'having']

const LOGICAL_KEYS = new Set(['AND', 'OR', 'NOT'])

type QueryHookCall = {
  model: string
  operation: string
  args: Record<string, unknown>
  query: (args: Record<string, unknown>) => Promise<unknown>
}

type ChainableOperation = {
  withLockContext(lockContext: LockContext): ChainableOperation
  audit(config: AuditConfig): ChainableOperation
  then: PromiseLike<{
    data?: unknown
    failure?: { message: string }
  }>['then']
}

export type ExtensionDeps = {
  encryptionClient: EncryptionClient
  prisma: PrismaNamespaceLike
  byModel: Map<string, ModelTableMeta>
  lockContext?: LockContext
  audit?: AuditConfig
}

/**
 * Build the Prisma client-extension object (the argument to `$extends`) that
 * makes registered models transparently encrypt on write and decrypt on read.
 *
 * What it deliberately does NOT do: service encrypted filters. Prisma lowers
 * Json comparisons with a column-side `::jsonb` cast that bypasses the
 * `eql_v3` domain operators (silent zero rows), and range filters on Json
 * don't exist — so any encrypted column referenced through the typed `where`
 * / `orderBy` / `distinct` / `cursor` / `having` surface throws
 * {@link PrismaEncryptedColumnError}. Encrypted search goes through the
 * `where` fragment builders + `$queryRawEncrypted`.
 *
 * v1 limits, by design:
 * - Nested writes/reads (relation `create`/`include`) are passed through
 *   untouched — only the intercepted model's own fields are processed.
 * - Field-update operator objects (`{ set: … }`) are not unwrapped; write
 *   plain values to encrypted fields.
 */
export function createEncryptedExtension(deps: ExtensionDeps): unknown {
  const { encryptionClient, prisma, byModel, lockContext, audit } = deps

  function runOperation(op: ChainableOperation) {
    const withLock = lockContext ? op.withLockContext(lockContext) : op
    if (audit) withLock.audit(audit)
    return withLock
  }

  async function unwrap<T>(op: ChainableOperation, what: string): Promise<T> {
    const result = await runOperation(op)
    if (result.failure) {
      throw new PrismaEncryptionError(
        `[prisma v3]: ${what} failed: ${result.failure.message}`,
        result.failure as never,
      )
    }
    return result.data as T
  }

  // -------------------------------------------------------------------------
  // Typed-query guard
  // -------------------------------------------------------------------------

  function throwGuard(
    meta: ModelTableMeta,
    field: string,
    clause: string,
  ): never {
    throw new PrismaEncryptedColumnError(
      `[prisma v3]: encrypted column "${field}" of model "${meta.modelName}" cannot be used in a typed \`${clause}\` — Prisma's Json lowering bypasses the eql_v3 operators (filters would silently match nothing). Use the encrypted where/orderBy fragment builders with $queryRawEncrypted instead.`,
      { model: meta.modelName, field, clause },
    )
  }

  function guardWhere(
    meta: ModelTableMeta,
    where: unknown,
    clause: string,
  ): void {
    if (where == null || typeof where !== 'object') return
    for (const entry of Array.isArray(where) ? where : [where]) {
      if (entry == null || typeof entry !== 'object') continue
      for (const [key, value] of Object.entries(entry)) {
        if (LOGICAL_KEYS.has(key)) {
          guardWhere(meta, value, clause)
        } else if (meta.encryptedProps.has(key)) {
          throwGuard(meta, key, clause)
        }
        // Any other object value is a relation filter — a DIFFERENT model's
        // fields — so it is deliberately not recursed.
      }
    }
  }

  function guardKeyed(
    meta: ModelTableMeta,
    value: unknown,
    clause: string,
  ): void {
    if (value == null) return
    if (typeof value === 'string') {
      if (meta.encryptedProps.has(value)) throwGuard(meta, value, clause)
      return
    }
    for (const entry of Array.isArray(value) ? value : [value]) {
      if (typeof entry === 'string') {
        if (meta.encryptedProps.has(entry)) throwGuard(meta, entry, clause)
      } else if (entry != null && typeof entry === 'object') {
        for (const key of Object.keys(entry)) {
          if (meta.encryptedProps.has(key)) throwGuard(meta, key, clause)
        }
      }
    }
  }

  function guardArgs(
    meta: ModelTableMeta,
    args: Record<string, unknown>,
  ): void {
    for (const clause of GUARDED_CLAUSES) {
      if (!(clause in args)) continue
      const value = args[clause]
      if (clause === 'where' || clause === 'having') {
        guardWhere(meta, value, clause)
      } else {
        guardKeyed(meta, value, clause)
      }
    }
  }

  // -------------------------------------------------------------------------
  // Write path
  // -------------------------------------------------------------------------

  /**
   * `null` on an encrypted field must reach the database as SQL NULL. Prisma
   * writes a plain `null` on a Json field as JSON `null`, which fails the
   * eql_v3 domain CHECK — so it is rewritten to `Prisma.DbNull`. `undefined`
   * is left alone: in Prisma it means "field not provided".
   */
  function normalizeNulls(
    meta: ModelTableMeta,
    input: Record<string, unknown>,
    row: Record<string, unknown>,
  ): Record<string, unknown> {
    const out = { ...row }
    for (const prop of meta.encryptedProps) {
      if (!(prop in out)) continue
      if (input[prop] === undefined) {
        // "Field not provided" must survive encryption untouched — encrypt
        // helpers may collapse undefined to null, which would otherwise be
        // promoted to DbNull below and null out the column on update.
        out[prop] = undefined
      } else if (out[prop] === null) {
        out[prop] = prisma.DbNull
      }
    }
    return out
  }

  async function encryptData(
    meta: ModelTableMeta,
    data: unknown,
  ): Promise<unknown> {
    if (Array.isArray(data)) {
      const encrypted = await unwrap<Record<string, unknown>[]>(
        encryptionClient.bulkEncryptModels(
          data as never,
          meta.table as never,
        ) as unknown as ChainableOperation,
        'encrypting model data',
      )
      return encrypted.map((row, i) =>
        normalizeNulls(meta, data[i] as Record<string, unknown>, row),
      )
    }
    if (data == null || typeof data !== 'object') return data
    const encrypted = await unwrap<Record<string, unknown>>(
      encryptionClient.encryptModel(
        data as never,
        meta.table as never,
      ) as unknown as ChainableOperation,
      'encrypting model data',
    )
    return normalizeNulls(meta, data as Record<string, unknown>, encrypted)
  }

  // -------------------------------------------------------------------------
  // Read path
  // -------------------------------------------------------------------------

  async function decryptResult(
    meta: ModelTableMeta,
    result: unknown,
  ): Promise<unknown> {
    if (result == null) return result
    if (Array.isArray(result)) {
      const rows = await unwrap<Record<string, unknown>[]>(
        encryptionClient.bulkDecryptModels(
          result as never,
        ) as unknown as ChainableOperation,
        'decrypting result rows',
      )
      return rows.map((row) => reconstructRow(meta, row))
    }
    if (typeof result !== 'object') return result
    const row = await unwrap<Record<string, unknown>>(
      encryptionClient.decryptModel(
        result as never,
      ) as unknown as ChainableOperation,
      'decrypting result row',
    )
    return reconstructRow(meta, row)
  }

  // -------------------------------------------------------------------------
  // The hook
  // -------------------------------------------------------------------------

  return {
    name: 'cipherstash-eql-v3',
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }: QueryHookCall) {
          const meta = byModel.get(model)
          if (!meta) return query(args)

          guardArgs(meta, args)

          let nextArgs = args
          const dataKeys = DATA_ARGS[operation]
          if (dataKeys) {
            nextArgs = { ...args }
            for (const key of dataKeys) {
              if (key in nextArgs) {
                nextArgs[key] = await encryptData(meta, nextArgs[key])
              }
            }
          }

          const result = await query(nextArgs)
          if (!ROW_RESULT_OPS.has(operation)) return result
          return decryptResult(meta, result)
        },
      },
    },
  }
}
