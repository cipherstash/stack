/**
 * Type-level pin of a real v3 asymmetry: audit metadata is available on the
 * encrypt-side operations (which are chainable) but NOT on `decryptModel` /
 * `bulkDecryptModels`, which return a bare `Promise<Result<…>>` rather than a
 * chainable operation. Documented here as an executable invariant so the gap
 * (v2's `decryptModel().audit(...)` has no v3 equivalent) can't silently change.
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

  it('does NOT expose .audit()/.withLockContext() on decryptModel (bare Promise)', () => {
    const result = typed.decryptModel({ email: {} as never }, users)
    // A Promise, not a chainable operation — no audit/lock-context hook.
    expectTypeOf(result).not.toHaveProperty('audit')
    expectTypeOf(result).not.toHaveProperty('withLockContext')
  })
})
