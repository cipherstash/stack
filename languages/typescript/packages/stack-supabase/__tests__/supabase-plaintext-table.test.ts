import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import type { EncryptionFactory, Introspector } from '../src/create'
import { makeEncryptedSupabase } from '../src/create'
import type { IntrospectionData } from '../src/introspect'
import {
  createMockEncryptionClient,
  createMockSupabase,
  isFakeEnvelope,
} from './helpers/supabase-mock'

/**
 * Tables with NO encrypted columns ("plaintext tables").
 *
 * The adapter registers every table it knows about with its query builder, but
 * `Encryption({ schemas })` only receives tables that carry at least one
 * encrypted column — it rejects an empty schema list, and a plaintext table has
 * nothing for it to do. Both real engines refuse a model operation on a table
 * they were not initialized with: the native client resolves
 * `decryptModel`/`bulkDecryptModels` to a "not initialized with" failure, and
 * the WASM client throws from `requireTable` for decrypts AND encrypts. So any
 * read of a plaintext table — or a mutation with `.select()` — used to fail
 * with `Failed to decrypt model: [eql/v3]: decryptModel received a table this
 * client was not initialized with`.
 *
 * The shared `createMockEncryptionClient` ignores the table argument, which is
 * why the existing suites never saw it. The factory below enforces the
 * registration contract the real engines enforce, so these tests fail the way
 * production did.
 */

/** The wording each real engine uses: the native client's `unknownTableFailure`
 * for decrypts, the WASM client's `requireTable` for encrypts. */
const notInitialized = (method: string, tableName: string) =>
  method.toLowerCase().includes('decrypt')
    ? '[eql/v3]: decryptModel received a table this client was not initialized with — pass one of the tables given to Encryption({ schemas })'
    : `[eql/v3]: table "${tableName}" is not one this client was initialized with — pass a table given to Encryption({ schemas })`

function failed(message: string) {
  const op = {
    withLockContext: () => op,
    audit: () => op,
    then: (
      onfulfilled?: ((value: unknown) => unknown) | null,
      onrejected?: ((reason: unknown) => unknown) | null,
    ) =>
      Promise.resolve({
        failure: { type: 'DecryptionError', message },
      }).then(onfulfilled, onrejected),
  }
  return op
}

/**
 * An `Encryption` stand-in that, like both real engines, only serves the tables
 * it was initialized with. Records what it was given so a test can assert the
 * plaintext table really was left out.
 */
function registryEnforcingFactory() {
  const registered: string[] = []
  const calls: string[] = []

  const factory: EncryptionFactory = async ({ schemas }) => {
    registered.push(...schemas.map((t) => t.tableName))
    const inner = createMockEncryptionClient() as unknown as Record<
      string,
      (...args: unknown[]) => unknown
    >
    const guarded =
      (method: string) =>
      (input: unknown, table: AnyV3Table | undefined, ...rest: unknown[]) => {
        calls.push(`${method}:${table?.tableName ?? '<none>'}`)
        if (table && !registered.includes(table.tableName)) {
          return failed(notInitialized(method, table.tableName))
        }
        return inner[method](input, table, ...rest)
      }
    return {
      ...inner,
      encryptModel: guarded('encryptModel'),
      bulkEncryptModels: guarded('bulkEncryptModels'),
      decryptModel: guarded('decryptModel'),
      bulkDecryptModels: guarded('bulkDecryptModels'),
    } as unknown as EncryptionClient
  }

  return { factory, registered, calls }
}

const introspection: IntrospectionData = {
  tables: [
    {
      tableName: 'users',
      columns: [
        { columnName: 'id', domainName: null },
        { columnName: 'email', domainName: 'eql_v3_text_search' },
      ],
    },
    {
      tableName: 'audit_log',
      columns: [
        { columnName: 'id', domainName: null },
        { columnName: 'action', domainName: null },
      ],
    },
  ],
  unmodelled: new Map(),
  eqlVersion: '3.0.4',
}

const introspector: Introspector = {
  introspect: async () => introspection,
  eqlRequiresQueryDomains: () => false,
}

const auditRows = [
  { id: 1, action: 'login' },
  { id: 2, action: 'logout' },
]

async function introspectedClient(resultData: unknown) {
  const encryption = registryEnforcingFactory()
  const supabase = createMockSupabase(resultData)
  const es = await makeEncryptedSupabase(encryption.factory, introspector)(
    supabase.client as never,
    { databaseUrl: 'postgres://x' },
  )
  return { es, encryption, supabase }
}

const users = encryptedTable('users', { email: types.TextSearch('email') })
const auditLog = encryptedTable('audit_log', {})

async function declaredClient(resultData: unknown) {
  const encryption = registryEnforcingFactory()
  const supabase = createMockSupabase(resultData)
  const es = await makeEncryptedSupabase(encryption.factory, null)(
    supabase.client as never,
    { schemas: { users, audit_log: auditLog } },
  )
  return { es, encryption, supabase }
}

describe.each([
  ['introspection mode', introspectedClient],
  ['declared mode', declaredClient],
] as const)('plaintext table — %s', (_mode, build) => {
  it('leaves the plaintext table out of Encryption({ schemas })', async () => {
    const { encryption } = await build([])
    expect(encryption.registered).toEqual(['users'])
  })

  it('reads every row of a plaintext table', async () => {
    const { es, encryption } = await build(auditRows)
    const { data, error } = await es.from('audit_log').select('id, action')

    expect(error).toBeNull()
    expect(data).toEqual(auditRows)
    // Nothing to decrypt, so the encryption client is not consulted at all.
    expect(encryption.calls).toEqual([])
  })

  it('reads a single row of a plaintext table', async () => {
    const { es } = await build(auditRows[0])
    const { data, error } = await es
      .from('audit_log')
      .select('id, action')
      .eq('id', 1)
      .single()

    expect(error).toBeNull()
    expect(data).toEqual(auditRows[0])
  })

  it('reads a plaintext table with throwOnError without throwing', async () => {
    const { es } = await build(auditRows)
    const { data } = await es
      .from('audit_log')
      .select('id, action')
      .throwOnError()
    expect(data).toEqual(auditRows)
  })

  it('inserts into a plaintext table and returns the row via .select()', async () => {
    const { es, encryption, supabase } = await build([auditRows[0]])
    const { data, error } = await es
      .from('audit_log')
      .insert({ id: 1, action: 'login' })
      .select('id, action')

    expect(error).toBeNull()
    expect(data).toEqual([auditRows[0]])
    // The row went to PostgREST exactly as written — no encrypt step ran.
    expect(supabase.callsFor('insert')[0].args[0]).toEqual({
      id: 1,
      action: 'login',
    })
    expect(encryption.calls).toEqual([])
  })

  it('bulk-inserts into a plaintext table', async () => {
    const { es, supabase } = await build(auditRows)
    const { data, error } = await es
      .from('audit_log')
      .insert(auditRows)
      .select('id, action')

    expect(error).toBeNull()
    expect(data).toEqual(auditRows)
    expect(supabase.callsFor('insert')[0].args[0]).toEqual(auditRows)
  })

  it('still encrypts and decrypts the encrypted table on the same instance', async () => {
    const { es, encryption, supabase } = await build([
      { id: 1, email: 'a@example.com' },
    ])
    const { data, error } = await es
      .from('users')
      .insert({ id: 1, email: 'a@example.com' })
      .select('id, email')

    expect(error).toBeNull()
    expect(data).toEqual([{ id: 1, email: 'a@example.com' }])
    const sent = supabase.callsFor('insert')[0].args[0] as Record<
      string,
      unknown
    >
    expect(isFakeEnvelope(sent.email)).toBe(true)
    expect(encryption.calls).toEqual([
      'encryptModel:users',
      'bulkDecryptModels:users',
    ])
  })
})
