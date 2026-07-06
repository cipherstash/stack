import type { EncryptionClient } from '@/encryption'
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { AnyV3Table } from '@/eql/v3'
import type { LockContext } from '@/identity'

/**
 * The slice of the generated client's `Prisma` namespace the integration
 * needs, injected by the caller. It cannot be imported here: `Prisma.sql`
 * and `Prisma.DbNull` are exported by the USER'S generated client (Prisma 7
 * generates to a caller-chosen path), not by a package this library could
 * resolve.
 */
export interface PrismaNamespaceLike {
  /** `Prisma.sql` — callable with a plain strings array + values. */
  sql: (strings: ReadonlyArray<string>, ...values: unknown[]) => unknown
  /** `Prisma.DbNull` — writes SQL NULL (vs JSON `null`) to a Json column. */
  DbNull: unknown
}

/**
 * Structural view of a PrismaClient instance — no dependency on
 * `@prisma/client` (mirrors `SupabaseClientLike`).
 */
export interface PrismaClientLike {
  $extends(extension: unknown): unknown
  $queryRaw(query: unknown, ...values: unknown[]): Promise<unknown>
}

/** An opaque `Prisma.sql` fragment (the return of the injected tag). */
export type SqlFragment = unknown

/** Per-call encryption options, mirroring the Supabase builder's surface. */
export type EncryptedCallOpts = {
  lockContext?: LockContext
  audit?: AuditConfig
}

export type EncryptedPrismaConfig<Client extends PrismaClientLike> = {
  encryptionClient: EncryptionClient
  prismaClient: Client
  /** The `Prisma` namespace from the caller's generated client. */
  prisma: PrismaNamespaceLike
  /** Prisma model name → v3 table schema, e.g. `{ User: users }`. */
  tables: Record<string, AnyV3Table>
  /** Applied to every extension encrypt/decrypt operation. */
  lockContext?: LockContext
  /** Applied to every extension encrypt/decrypt operation. */
  audit?: AuditConfig
}
