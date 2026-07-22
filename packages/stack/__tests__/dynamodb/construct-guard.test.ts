/**
 * Construction-time client/table EQL-version guard (#725, thread 13).
 *
 * A v3 table handed to a client that was NOT built in EQL v3 mode for it (a
 * v2-mode client, or one initialised for a different schema set) otherwise
 * fails only much later, deep inside the FFI, with an opaque deserialization
 * error. `encryptedDynamoDB`'s operation methods guard against that mismatch
 * the moment a table is supplied — the earliest point at which BOTH the client
 * and the table version are known — and throw a clear, actionable Error.
 *
 * This suite is pure: it drives the guard with stub clients whose
 * `getEncryptConfig()` reports which tables the client knows about, so it needs
 * neither credentials nor a live FFI round-trip. The stub operation methods
 * throw if ever reached, proving the guard fires BEFORE any client call.
 */
import { describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { encryptedTable as encryptedTableV3, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'

const usersV3 = encryptedTableV3('users_v3', {
  email: types.TextEq('email'),
})

const usersV2 = encryptedTableV2('users_v2', {
  email: encryptedColumn('email').equality(),
})

/**
 * A stub client that reports the given table names in its encrypt config. The
 * operation methods throw if invoked, so any test that reaches them (rather than
 * the synchronous guard) fails loudly.
 */
function stubClient(knownTables: string[]) {
  const tables = Object.fromEntries(knownTables.map((t) => [t, {}]))
  const unreached = () => {
    throw new Error('FFI operation reached — guard did not fire first')
  }
  return {
    getEncryptConfig: () => ({ v: 1, tables }),
    encryptModel: unreached,
    bulkEncryptModels: unreached,
    decryptModel: unreached,
    bulkDecryptModels: unreached,
    // biome-ignore lint/suspicious/noExplicitAny: deliberately permissive test-stub client
  } as any
}

describe('encryptedDynamoDB client/table version guard', () => {
  it('throws a clear version-mismatch error for a v3 table on a client that does not know it', () => {
    // A client built for other (e.g. v2) schemas: `users_v3` is absent.
    const dynamo = encryptedDynamoDB({ encryptionClient: stubClient([]) })

    expect(() =>
      dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV3),
    ).toThrowError(/version mismatch/i)
    expect(() =>
      dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV3),
    ).toThrowError(/v3/)
  })

  it('names the offending table and how to fix it', () => {
    const dynamo = encryptedDynamoDB({ encryptionClient: stubClient([]) })
    let message = ''
    try {
      dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV3)
    } catch (e) {
      message = (e as Error).message
    }
    expect(message).toContain('users_v3')
    expect(message).toMatch(/EncryptionV3|eqlVersion/)
  })

  it('guards every operation method, not just encryptModel', () => {
    const dynamo = encryptedDynamoDB({ encryptionClient: stubClient([]) })
    expect(() =>
      dynamo.bulkEncryptModels([{ pk: 'a', email: 'a@b.com' }], usersV3),
    ).toThrowError(/version mismatch/i)
    expect(() =>
      dynamo.decryptModel({ pk: 'a', email__source: 'ct' }, usersV3),
    ).toThrowError(/version mismatch/i)
    expect(() =>
      dynamo.bulkDecryptModels([{ pk: 'a', email__source: 'ct' }], usersV3),
    ).toThrowError(/version mismatch/i)
  })

  it('does NOT throw when a v3 table is registered with the client (matching versions)', () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: stubClient(['users_v3']),
    })
    // Constructing the operation must not throw; the stub op methods are never
    // awaited, so the "unreached" guard inside them is not tripped.
    expect(() =>
      dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV3),
    ).not.toThrow()
  })

  it('does NOT throw for a v2 table on a v2-mode client (matching versions)', () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: stubClient(['users_v2']),
    })
    expect(() =>
      dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV2),
    ).not.toThrow()
  })

  it('does NOT throw a v3 table on a client whose config cannot be read (cannot determine version)', () => {
    // A client shape with no getEncryptConfig — the guard cannot prove a
    // mismatch, so it must not false-positive.
    const unreached = () => {
      throw new Error('FFI operation reached — guard did not fire first')
    }
    const dynamo = encryptedDynamoDB({
      encryptionClient: {
        encryptModel: unreached,
        bulkEncryptModels: unreached,
        decryptModel: unreached,
        bulkDecryptModels: unreached,
        // biome-ignore lint/suspicious/noExplicitAny: deliberately permissive test-stub client
      } as any,
    })
    expect(() =>
      dynamo.encryptModel({ pk: 'a', email: 'a@b.com' }, usersV3),
    ).not.toThrow()
  })
})
