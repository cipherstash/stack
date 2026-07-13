import type { EncryptionClient } from '@cipherstash/stack/encryption'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { EncryptionErrorTypes } from '@cipherstash/stack/errors'
import {
  encryptedColumn,
  encryptedTable as encryptedTableV2,
} from '@cipherstash/stack/schema'
import { describe, expect, it } from 'vitest'
import { EncryptedQueryBuilderImpl } from '../src/query-builder'
import { EncryptedQueryBuilderV3Impl } from '../src/query-builder-v3'
import {
  createMockEncryptionClient,
  createMockSupabase,
  fakeEnvelope,
  operation,
} from './helpers/supabase-mock'

/**
 * Regression coverage for #626: the query builder's catch block used to hardcode
 * `encryptionError: undefined`, so the typed `EncryptedSupabaseError.encryptionError`
 * field was dead. The v2 tests pin that a genuine encryption failure now threads its
 * `EncryptionError` through the shared base `execute()` catch, while a plain
 * (non-encryption) throw leaves it unset. The v3 test covers the dialect's own
 * `encryptionFailure` path, which synthesizes an `EncryptionError` for a
 * query-term contract violation (no operation failure to wrap).
 */

const usersV2 = encryptedTableV2('users', {
  email: encryptedColumn('email').freeTextSearch().equality(),
})

const usersV3 = encryptedTable('users', {
  email: types.TextEq('email'),
})

/** A chainable op that resolves to `{ failure }`, like a real failed operation. */
function failingOperation(failure: { type: string; message: string }) {
  const op = {
    withLockContext: () => op,
    audit: () => op,
    then: (
      onfulfilled?: ((value: { failure: typeof failure }) => unknown) | null,
      onrejected?: ((reason: unknown) => unknown) | null,
    ) => Promise.resolve({ failure }).then(onfulfilled, onrejected),
  }
  return op
}

describe('EncryptedSupabaseError.encryptionError (#626)', () => {
  it('v2: threads the EncryptionError through on an encryption failure', async () => {
    const failure = {
      type: EncryptionErrorTypes.EncryptionError,
      message: 'zerokms unreachable',
    }
    const encryptionClient = createMockEncryptionClient() as unknown as Record<
      string,
      unknown
    >
    encryptionClient['encryptModel'] = () => failingOperation(failure)

    const { client: supabase } = createMockSupabase()
    const builder = new EncryptedQueryBuilderImpl(
      'users',
      usersV2,
      encryptionClient as unknown as EncryptionClient,
      supabase,
    )

    const { data, error } = await builder.insert({ email: 'ada@example.com' })

    expect(data).toBeNull()
    expect(error).not.toBeNull()
    expect(error?.encryptionError).toEqual(failure)
    expect(error?.encryptionError?.type).toBe(
      EncryptionErrorTypes.EncryptionError,
    )
  })

  it('v2: leaves encryptionError unset on a plain (non-encryption) error', async () => {
    const encryptionClient = createMockEncryptionClient()
    const { client: supabase } = createMockSupabase()
    // Make the underlying supabase call throw a non-encryption error: an insert
    // with no encrypted columns skips encryption and goes straight to the wire.
    supabase.from = () => {
      throw new Error('PostgREST is down')
    }

    const builder = new EncryptedQueryBuilderImpl(
      'users',
      usersV2,
      encryptionClient,
      supabase,
    )

    const { data, error } = await builder.insert({ id: 1 } as never)

    expect(data).toBeNull()
    expect(error?.message).toContain('PostgREST is down')
    expect(error?.encryptionError).toBeUndefined()
  })

  it('v3: synthesizes an EncryptionError for a query-term contract violation', async () => {
    // The v3 dialect's own `encryptionFailure` path has no operation failure to
    // wrap for its contract-violation cases, so it synthesizes an EncryptionError.
    // Drive it directly: a two-element `in` list whose bulkEncrypt returns one
    // term trips the length-mismatch check. (The base `execute()` threading is
    // already covered by the v2 test above; overriding `encryptModel` here would
    // only re-run that shared path, not this v3-specific branch.)
    const encryptionClient = createMockEncryptionClient() as unknown as {
      bulkEncrypt: (...args: unknown[]) => unknown
    }
    encryptionClient.bulkEncrypt = () =>
      operation([{ data: fakeEnvelope('ada', 'email') }])

    const { client: supabase } = createMockSupabase()
    const { error, status } = await new EncryptedQueryBuilderV3Impl(
      'users',
      usersV3,
      encryptionClient as unknown as EncryptionClient,
      supabase,
      ['id', 'email'],
    )
      .select('id')
      .in('email', ['ada@example.com', 'grace@example.com'])

    expect(status).toBe(500)
    expect(error?.encryptionError?.type).toBe(
      EncryptionErrorTypes.EncryptionError,
    )
    expect(error?.encryptionError?.message).toMatch(
      /1 term(s)? for 2 value(s)?/,
    )
  })
})
