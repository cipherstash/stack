/**
 * Live encrypted-JSON querying for the v3 supabase adapter (#650): real crypto,
 * real PostgREST (as `anon`), real `public.eql_v3_json` domain.
 *
 * What this uniquely proves (the unit suite runs against mocks):
 * - `contains()` reaches the `eql_v3."@>"(eql_v3_json, eql_v3_json)` overload
 *   through PostgREST's column-type cast of the `cs.` operand, with a real
 *   storage-encrypted needle (probe-verified wire form; see #650).
 * - `selectorEq`/`selectorNe` — equality-at-a-path compiled to containment of
 *   the reconstructed needle — return the right ROWS, including the documented
 *   `ne` semantics: rows whose document lacks the path entirely are INCLUDED.
 * - The `anon` grants cover the ste_vec functions the operator expands to.
 *
 * Selector ORDERING is deliberately absent: not expressible over PostgREST
 * until cipherstash/encrypt-query-language#407 lands. Drizzle's
 * `json-selector.integration.test.ts` proves ordering semantics.
 */

import type { JsonDocument } from '@cipherstash/stack/eql/v3'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { encryptedSupabaseV3 } from '../src/index.js'
import { makePostgrestClient, reloadSchemaCache } from './helpers/pgrest'

const TABLE = 'protect_ci_v3_supabase_json'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

const sql = postgres(databaseUrl(), { prepare: false })

const docs = encryptedTable(TABLE, {
  payload: types.Json('payload'),
})

const DOCS: Record<string, JsonDocument> = {
  ada: { user: { email: 'ada@example.com', role: 'admin' }, age: 30 },
  grace: { user: { email: 'grace@example.com', role: 'admin' }, age: 20 },
  zoe: { user: { email: 'zoe@example.com', role: 'analyst' }, age: 40 },
  // No `$.age` and no `$.user.role` — exercises absent-path semantics
  // (excluded by contains/selectorEq, INCLUDED by selectorNe).
  norole: { user: { email: 'norole@example.com' } },
}

type Instance = Awaited<ReturnType<typeof encryptedSupabaseV3>>
let instance: Instance

function from() {
  return (instance as never as Instance)
    .from<{ row_key: string; payload: JsonDocument }>(TABLE, docs as never)
    .select('row_key')
    .eq('test_run_id', RUN)
}

async function rowKeys(
  q: PromiseLike<{ data: unknown; error: { message: string } | null }>,
): Promise<string[]> {
  const { data, error } = await q
  if (error) throw new Error(error.message)
  return ((data as { row_key: string }[]) ?? []).map((r) => r.row_key).sort()
}

beforeAll(async () => {
  await sql.unsafe(`
    CREATE TABLE IF NOT EXISTS public.${TABLE} (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      row_key text NOT NULL,
      test_run_id text NOT NULL,
      payload public.eql_v3_json
    )
  `)
  await sql.unsafe(
    `GRANT SELECT, INSERT ON public.${TABLE} TO anon, authenticated`,
  )
  await reloadSchemaCache(sql, TABLE)

  instance = await encryptedSupabaseV3(makePostgrestClient(), {
    schemas: { [TABLE]: docs } as never,
    databaseUrl: databaseUrl(),
  })

  const models = Object.entries(DOCS).map(([rowKey, payload]) => ({
    row_key: rowKey,
    test_run_id: RUN,
    payload,
  }))
  const { error } = await (instance as never as Instance)
    .from(TABLE, docs as never)
    .insert(models)
  if (error) throw new Error(`seed insert: ${error.message}`)
}, 120_000)

afterAll(async () => {
  await sql.unsafe(`DELETE FROM public.${TABLE} WHERE test_run_id = '${RUN}'`)
  await sql.end()
})

describe('encrypted containment (contains)', () => {
  it('matches rows containing a nested sub-document', async () => {
    expect(
      await rowKeys(from().contains('payload', { user: { role: 'admin' } })),
    ).toEqual(['ada', 'grace'])
  })

  it('a multi-leaf needle requires EVERY leaf to match', async () => {
    expect(
      await rowKeys(
        from().contains('payload', {
          user: { role: 'admin' },
          age: 30,
        }),
      ),
    ).toEqual(['ada'])
  })

  it('matches nothing for an absent value', async () => {
    expect(await rowKeys(from().contains('payload', { age: 99 }))).toEqual([])
  })

  it('raw .filter(col, "cs", subdoc) is the same query', async () => {
    expect(await rowKeys(from().filter('payload', 'cs', { age: 40 }))).toEqual([
      'zoe',
    ])
  })
})

describe('selector equality (selectorEq)', () => {
  it('matches the row carrying the value at the path', async () => {
    expect(await rowKeys(from().selectorEq('payload', '$.age', 30))).toEqual([
      'ada',
    ])
  })

  it('works on nested paths and string leaves', async () => {
    expect(
      await rowKeys(from().selectorEq('payload', '$.user.role', 'analyst')),
    ).toEqual(['zoe'])
  })

  it('an absent path matches nothing', async () => {
    expect(
      await rowKeys(from().selectorEq('payload', '$.user.missing', 'x')),
    ).toEqual([])
  })
})

describe('selector inequality (selectorNe)', () => {
  it('includes rows with a different value AND rows lacking the path', async () => {
    // Documented semantics (mirrors the Drizzle selector `ne`): NOT-contains,
    // and a document without the path never contains — so `norole` is in.
    expect(
      await rowKeys(from().selectorNe('payload', '$.user.role', 'admin')),
    ).toEqual(['norole', 'zoe'])
  })

  it('ne against an absent-everywhere value returns every row', async () => {
    expect(await rowKeys(from().selectorNe('payload', '$.age', 99))).toEqual([
      'ada',
      'grace',
      'norole',
      'zoe',
    ])
  })
})

describe('guards hold on the live surface', () => {
  it('matches() on the JSON column throws the steer', () => {
    expect(() => from().matches('payload', 'admin')).toThrow(
      /encrypted JSON column/,
    )
  })

  it('scalar ops on the JSON column are rejected by capability', async () => {
    const { error, status } = await from().filter('payload', 'eq', { a: 1 })
    expect(status).toBe(500)
    expect(error?.message).toMatch(/does not support equality/)
  })
})
