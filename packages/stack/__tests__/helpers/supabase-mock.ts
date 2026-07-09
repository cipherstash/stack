/**
 * Test doubles for the Supabase query-builder suites.
 *
 * The builders only touch a narrow slice of the encryption client and the
 * supabase client, so both are simulated: the encryption mock produces
 * deterministic fake envelopes (carrying the plaintext in `pt` so the fake
 * decrypt can undo them), and the supabase mock records every builder call.
 * This pins the WIRE ENCODING each dialect produces — the part of the adapter
 * that CI can verify without a live Supabase project.
 *
 * Extracted verbatim from `supabase-v3-builder.test.ts` so the 39-domain wire
 * sweep (`supabase-v3-matrix.test.ts`) drives the adapter through the exact
 * same doubles, and a change to either mock moves both suites together.
 */

import type { EncryptionClient } from '@/encryption'

export type FakeEnvelope = {
  v: 2
  i: { t: string; c: string }
  c: string
  hm: string
  pt: unknown
}

export function fakeEnvelope(value: unknown, column: string): FakeEnvelope {
  // `pt` is carried through `JSON.stringify` by the v3 filter path
  // (`encryptCollectedTerms`), so it must be JSON-serializable. A real
  // envelope only ever holds strings; normalize the two plaintext types that
  // are not — `Date` and `bigint` — rather than letting the mock throw where
  // the product would not. The `bigint` domains' samples are the only reason
  // this matters.
  const pt =
    value instanceof Date
      ? value.toISOString()
      : typeof value === 'bigint'
        ? value.toString()
        : value
  return {
    v: 2,
    i: { t: 'tbl', c: column },
    c: `ct:${String(pt)}`,
    hm: `hm:${String(pt)}`,
    pt,
  }
}

export function isFakeEnvelope(value: unknown): value is FakeEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    'pt' in value &&
    'c' in value &&
    'hm' in value
  )
}

/** A chainable operation resolving to `{ data }`, like the real ones. */
export function operation<T>(data: T) {
  const op = {
    withLockContext: () => op,
    audit: () => op,
    then: (
      onfulfilled?: ((value: { data: T }) => unknown) | null,
      onrejected?: ((reason: unknown) => unknown) | null,
    ) => Promise.resolve({ data }).then(onfulfilled, onrejected),
  }
  return op
}

type SchemaLike = {
  build(): { columns: Record<string, unknown> }
  buildColumnKeyMap?(): Record<string, string>
}

export function createMockEncryptionClient() {
  const encryptedProps = (table: SchemaLike): string[] =>
    table.buildColumnKeyMap
      ? Object.keys(table.buildColumnKeyMap())
      : Object.keys(table.build().columns)

  const client = {
    encrypt: (value: unknown, opts: { column: { getName(): string } }) =>
      operation(fakeEnvelope(value, opts.column.getName())),

    // v2 filter path: batch query terms as composite literals
    encryptQuery: (terms: Array<{ value: unknown }>) =>
      operation(terms.map((t) => `("${String(t.value)}")`)),

    encryptModel: (model: Record<string, unknown>, table: SchemaLike) => {
      const props = encryptedProps(table)
      const out: Record<string, unknown> = { ...model }
      for (const prop of props) {
        if (out[prop] != null) out[prop] = fakeEnvelope(out[prop], prop)
      }
      return operation(out)
    },

    bulkEncryptModels: (
      models: Record<string, unknown>[],
      table: SchemaLike,
    ) => {
      const props = encryptedProps(table)
      return operation(
        models.map((model) => {
          const out: Record<string, unknown> = { ...model }
          for (const prop of props) {
            if (out[prop] != null) out[prop] = fakeEnvelope(out[prop], prop)
          }
          return out
        }),
      )
    },

    decryptModel: (model: Record<string, unknown>) => {
      const out: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(model)) {
        out[key] = isFakeEnvelope(value) ? value.pt : value
      }
      return operation(out)
    },

    bulkDecryptModels: (models: Record<string, unknown>[]) =>
      operation(
        models.map((model) => {
          const out: Record<string, unknown> = {}
          for (const [key, value] of Object.entries(model)) {
            out[key] = isFakeEnvelope(value) ? value.pt : value
          }
          return out
        }),
      ),
  }

  return client as unknown as EncryptionClient
}

export type RecordedCall = { method: string; args: unknown[] }

export function createMockSupabase(resultData: unknown = []) {
  const calls: RecordedCall[] = []
  // biome-ignore lint/suspicious/noExplicitAny: test double for the supabase query builder
  const qb: any = {}
  const methods = [
    'select',
    'insert',
    'update',
    'upsert',
    'delete',
    'eq',
    'neq',
    'gt',
    'gte',
    'lt',
    'lte',
    'like',
    'ilike',
    'is',
    'in',
    'filter',
    'not',
    'or',
    'match',
    'order',
    'limit',
    'range',
    'single',
    'maybeSingle',
    'csv',
    'abortSignal',
    'throwOnError',
  ]
  for (const method of methods) {
    qb[method] = (...args: unknown[]) => {
      calls.push({ method, args })
      return qb
    }
  }
  qb.then = (
    onfulfilled?: ((value: unknown) => unknown) | null,
    onrejected?: ((reason: unknown) => unknown) | null,
  ) =>
    Promise.resolve({
      data: resultData,
      error: null,
      count: null,
      status: 200,
      statusText: 'OK',
    }).then(onfulfilled, onrejected)

  const client = { from: (_table: string) => qb }
  const callsFor = (method: string) => calls.filter((c) => c.method === method)

  return { client, calls, callsFor }
}
