import type { AnyV3Table } from '@/eql/v3'
import { PrismaEncryptionError } from './errors'
import { createEncryptedExtension } from './extension'
import {
  buildModelMap,
  buildTableMeta,
  type ModelTableMeta,
  reconstructRow,
} from './model-map'
import type {
  EncryptedCallOpts,
  EncryptedPrismaConfig,
  PrismaClientLike,
  SqlFragment,
} from './types'
import { createEncryptedWhere, type EncryptedWhere } from './where'

export interface EncryptedPrismaInstance<Client extends PrismaClientLike> {
  /**
   * The `$extends`-wrapped Prisma client: registered models transparently
   * encrypt on write and decrypt on read, and any encrypted column reaching
   * the typed `where`/`orderBy`/`distinct`/`cursor`/`having` surface throws
   * (Prisma's Json lowering bypasses the `eql_v3` operators — a typed filter
   * would silently match nothing).
   */
  client: Client
  /** Capability-checked `Prisma.sql` fragment builders for encrypted search. */
  where: EncryptedWhere
  /**
   * Run a raw query and decrypt the result rows against `table` (registered
   * or not), including `Date` reconstruction under the DB column names.
   */
  $queryRawEncrypted<
    T extends Record<string, unknown> = Record<string, unknown>,
  >(
    table: AnyV3Table,
    query: SqlFragment,
    opts?: EncryptedCallOpts,
  ): Promise<T[]>
}

/**
 * Create the encrypted Prisma wrapper for **EQL v3** schemas — tables
 * authored with `@cipherstash/stack/eql/v3` whose columns are native
 * `eql_v3.*` domains, declared as `Json` fields in `schema.prisma`.
 *
 * @example
 * ```typescript
 * import { PrismaClient, Prisma } from './generated/client'
 * import { EncryptionV3, encryptedTable, types } from '@cipherstash/stack/v3'
 * import { encryptedPrisma } from '@cipherstash/stack/eql/v3/prisma'
 *
 * const users = encryptedTable('users', {
 *   email: types.TextEq('email'),
 *   age:   types.IntegerOrd('age'),
 * })
 *
 * const encryption = await EncryptionV3({ schemas: [users] })
 * const { client, where, $queryRawEncrypted } = encryptedPrisma({
 *   encryptionClient: encryption,
 *   prismaClient: new PrismaClient({ adapter }),
 *   prisma: Prisma,
 *   tables: { User: users },
 * })
 *
 * // CRUD — transparent encrypt/decrypt
 * await client.user.create({ data: { email: 'a@b.com', age: 30 } })
 *
 * // Encrypted search — fragment builders + $queryRawEncrypted
 * const rows = await $queryRawEncrypted(
 *   users,
 *   Prisma.sql`SELECT * FROM users WHERE ${await where.eq(users.email, 'a@b.com')}`,
 * )
 * ```
 */
export function encryptedPrisma<Client extends PrismaClientLike>(
  config: EncryptedPrismaConfig<Client>,
): EncryptedPrismaInstance<Client> {
  const { encryptionClient, prismaClient, prisma, tables } = config
  const { byModel, byColumn } = buildModelMap(tables)

  const extension = createEncryptedExtension({
    encryptionClient,
    prisma,
    byModel,
    lockContext: config.lockContext,
    audit: config.audit,
  })
  const client = prismaClient.$extends(extension) as Client

  const where = createEncryptedWhere({ encryptionClient, prisma, byColumn })

  const metaByTable = new Map<AnyV3Table, ModelTableMeta>()
  for (const meta of byModel.values()) metaByTable.set(meta.table, meta)

  async function $queryRawEncrypted<
    T extends Record<string, unknown> = Record<string, unknown>,
  >(
    table: AnyV3Table,
    query: SqlFragment,
    opts?: EncryptedCallOpts,
  ): Promise<T[]> {
    const rows = await prismaClient.$queryRaw(query)
    if (!Array.isArray(rows) || rows.length === 0) return (rows ?? []) as T[]

    const meta = metaByTable.get(table) ?? buildTableMeta(table)

    const baseOp = encryptionClient.bulkDecryptModels(rows as never)
    const lockContext = opts?.lockContext ?? config.lockContext
    const audit = opts?.audit ?? config.audit
    const op = lockContext ? baseOp.withLockContext(lockContext) : baseOp
    if (audit) op.audit(audit)

    const result = await op
    if (result.failure) {
      throw new PrismaEncryptionError(
        `[prisma v3]: failed to decrypt raw query rows: ${result.failure.message}`,
        result.failure,
      )
    }
    return (result.data as Record<string, unknown>[]).map((row) =>
      reconstructRow(meta, row),
    ) as T[]
  }

  return { client, where, $queryRawEncrypted }
}

export {
  EncryptionOperatorError,
  PrismaEncryptedColumnError,
  PrismaEncryptionError,
} from './errors'
export { createEncryptedExtension } from './extension'
export type { ModelTableMeta } from './model-map'
export type {
  EncryptedCallOpts,
  EncryptedPrismaConfig,
  PrismaClientLike,
  PrismaNamespaceLike,
  SqlFragment,
} from './types'
export type { EncryptedWhere } from './where'
export { createEncryptedWhere } from './where'
