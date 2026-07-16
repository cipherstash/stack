/**
 * Query-type matrix for `@cipherstash/stack/wasm-inline`'s `encryptQuery` /
 * `encryptQueryBulk` (#662) — the WASM twin of the per-query-type coverage
 * the Drizzle/Supabase adapters have.
 *
 * Runs under Deno against real CipherStash credentials, one live term per
 * query type the surface supports:
 *
 *   | queryType        | column domain        | FFI index  |
 *   |------------------|----------------------|------------|
 *   | equality         | eql_v3_text_eq       | unique     |
 *   | freeTextSearch   | eql_v3_text_search   | match      |
 *   | orderAndRange    | eql_v3_integer_ord   | ore        |
 *   | searchableJson   | eql_v3_json          | ste_vec    |
 *   |   (string value) |   → ste_vec_selector |            |
 *   |   (object value) |   → ste_vec_term     |            |
 *
 * Every term must be EQL v3 and CIPHERTEXT-FREE (terms are needles matched
 * against stored values, never decrypted) — the two serde-boundary bugs this
 * suite's first run caught (undefined fields rejected; the bulk field is
 * `queries`) are exactly why each type needs a live crossing, not a mock.
 *
 * Skipped when any CS_* env var is missing, matching `roundtrip.test.ts`.
 */

import { assertEquals, assertExists } from 'jsr:@std/assert@^1.0.0'
import {
  Encryption,
  encryptedTable,
  types,
} from '@cipherstash/stack/wasm-inline'

const REQUIRED_ENV = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ACCESS_KEY',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
] as const

function envOrSkip(): Record<(typeof REQUIRED_ENV)[number], string> | null {
  const values = {} as Record<(typeof REQUIRED_ENV)[number], string>
  for (const key of REQUIRED_ENV) {
    const value = Deno.env.get(key)
    if (!value) return null
    values[key] = value
  }
  return values
}

const env = envOrSkip()

const catalog = encryptedTable('wasm_query_matrix', {
  email: types.TextEq('email'), // equality only
  bio: types.TextSearch('bio'), // free-text (also carries eq + ore)
  age: types.IntegerOrd('age'), // eq + order/range
  prefs: types.Json('prefs'), // searchable JSON (ste_vec)
})

/** A v3 query term must exist, be versioned 3, and carry NO ciphertext. */
function assertV3Term(term: unknown, label: string) {
  assertExists(term, `${label}: encryptQuery returned null`)
  const obj = term as Record<string, unknown>
  assertEquals(obj.v, 3, `${label}: term is not EQL v3`)
  assertEquals('c' in obj, false, `${label}: term carries ciphertext`)
}

Deno.test({
  name: 'stack/wasm-inline: encryptQuery covers every v3 query type',
  ignore: env === null,
  async fn() {
    const client = await Encryption({
      schemas: [catalog],
      config: {
        workspaceCrn: env!.CS_WORKSPACE_CRN,
        accessKey: env!.CS_CLIENT_ACCESS_KEY,
        clientId: env!.CS_CLIENT_ID,
        clientKey: env!.CS_CLIENT_KEY,
      },
    })

    // equality → unique index
    assertV3Term(
      await client.encryptQuery('alice@example.com', {
        table: catalog,
        column: catalog.email,
        queryType: 'equality',
      }),
      'equality',
    )

    // freeTextSearch → match index
    assertV3Term(
      await client.encryptQuery('needle phrase', {
        table: catalog,
        column: catalog.bio,
        queryType: 'freeTextSearch',
      }),
      'freeTextSearch',
    )

    // orderAndRange → ore index (numeric)
    assertV3Term(
      await client.encryptQuery(42, {
        table: catalog,
        column: catalog.age,
        queryType: 'orderAndRange',
      }),
      'orderAndRange',
    )

    // searchableJson, string value → ste_vec_selector (JSONPath)
    assertV3Term(
      await client.encryptQuery('$.theme', {
        table: catalog,
        column: catalog.prefs,
        queryType: 'searchableJson',
      }),
      'searchableJson/selector',
    )

    // searchableJson, object value → ste_vec_term (containment)
    assertV3Term(
      await client.encryptQuery(
        { theme: 'dark' },
        {
          table: catalog,
          column: catalog.prefs,
          queryType: 'searchableJson',
        },
      ),
      'searchableJson/containment',
    )

    // Omitted queryType → inference from the column's indexes (TextEq has
    // exactly one: unique), mirroring the native client.
    assertV3Term(
      await client.encryptQuery('bob@example.com', {
        table: catalog,
        column: catalog.email,
      }),
      'inference',
    )

    // Bulk: one round trip across mixed query types, position-stable with
    // nulls passing through.
    const bulk = await client.encryptQueryBulk([
      {
        value: 'alice@example.com',
        table: catalog,
        column: catalog.email,
        queryType: 'equality',
      },
      {
        value: null as unknown as string,
        table: catalog,
        column: catalog.email,
      },
      {
        value: 'needle',
        table: catalog,
        column: catalog.bio,
        queryType: 'freeTextSearch',
      },
      {
        value: 7,
        table: catalog,
        column: catalog.age,
        queryType: 'orderAndRange',
      },
      {
        value: { theme: 'dark' },
        table: catalog,
        column: catalog.prefs,
        queryType: 'searchableJson',
      },
    ])
    assertEquals(bulk.length, 5)
    assertV3Term(bulk[0], 'bulk/equality')
    assertEquals(bulk[1], null, 'bulk: null value must yield null')
    assertV3Term(bulk[2], 'bulk/freeTextSearch')
    assertV3Term(bulk[3], 'bulk/orderAndRange')
    assertV3Term(bulk[4], 'bulk/searchableJson')
  },
})
