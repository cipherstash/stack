import type { EncryptionError } from '@/errors'

/**
 * A v3 where/order builder was used against a column that cannot support it —
 * wrong capability for the operator, a storage-only column, a column from an
 * unregistered table, or an invalid operand.
 *
 * Thrown instead of falling back to a plain comparison: a v3 domain column
 * has no plaintext form, and mis-lowered SQL either fails the domain CHECK at
 * runtime or (worse) silently matches nothing. Same convention as the Drizzle
 * v3 operators.
 */
export class EncryptionOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      columnName?: string
      tableName?: string
      operator?: string
    },
  ) {
    super(message)
    this.name = 'EncryptionOperatorError'
  }
}

/**
 * An encrypted column was referenced through Prisma's TYPED query surface
 * (`where`, `orderBy`, `distinct`, `cursor`, `having`). Prisma lowers Json
 * comparisons with a column-side `::jsonb` cast that bypasses the `eql_v3`
 * domain operators, so a typed filter on an encrypted column silently returns
 * zero rows — the guard turns that into a loud error pointing at the
 * fragment builders.
 */
export class PrismaEncryptedColumnError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      model?: string
      field?: string
      clause?: string
    },
  ) {
    super(message)
    this.name = 'PrismaEncryptedColumnError'
  }
}

/** An encryption/decryption operation failed while servicing a Prisma call. */
export class PrismaEncryptionError extends Error {
  constructor(
    message: string,
    public readonly encryptionError?: EncryptionError,
  ) {
    super(message)
    this.name = 'PrismaEncryptionError'
  }
}
