/**
 * Type-level pin that audit + lock-context are chainable on BOTH the encrypt-side
 * operations AND `decryptModel` / `bulkDecryptModels`. The typed client's decrypt
 * methods now return a chainable {@link MappedDecryptOperation} (was a bare
 * `Promise<Result<…>>`), restoring the v2-era `decryptModel().audit(...)` surface
 * on the v3 client. Documented here as an executable invariant so the capability
 * can't silently regress.
 *
 * Runs via `pnpm test:types`.
 */
import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, typedClient, types } from '@/encryption/v3'

const users = encryptedTable('u', { email: types.TextEq('email') })
declare const client: EncryptionClient
const typed = typedClient(client, users)

describe('v3 typed client audit/lock-context chainability (types)', () => {
  it('exposes .audit() and .withLockContext() on the encrypt operation', () => {
    const op = typed.encrypt('x', { table: users, column: users.email })
    expectTypeOf(op).toHaveProperty('audit')
    expectTypeOf(op).toHaveProperty('withLockContext')
  })

  it('exposes .audit()/.withLockContext() on decryptModel (chainable operation)', () => {
    const op = typed.decryptModel({ email: {} as never }, users)
    // A chainable operation, not a bare Promise — audit + lock-context hooks.
    expectTypeOf(op).toHaveProperty('audit')
    expectTypeOf(op).toHaveProperty('withLockContext')
  })

  it('exposes .audit()/.withLockContext() on bulkDecryptModels (chainable operation)', () => {
    const op = typed.bulkDecryptModels([{ email: {} as never }], users)
    expectTypeOf(op).toHaveProperty('audit')
    expectTypeOf(op).toHaveProperty('withLockContext')
  })
})
