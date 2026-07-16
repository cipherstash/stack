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
 * Wire shapes differ by kind — which is exactly what this suite pins:
 * SCALAR terms are v3 envelopes (`{v: 3, i, …}`); a JSON CONTAINMENT
 * needle is a strict `{sv: [query-entry]}` with no version field; a
 * SELECTOR query returns the BARE selector-hash string (v3 has no
 * encrypted-selector envelope — bind as the text argument of `->`/`->>`).
 * All are CIPHERTEXT-FREE. The boundary bugs this suite's first runs
 * caught (undefined fields rejected by serde; the bulk field is `queries`;
 * the ore→ope swap; both JSON shapes) are exactly why each type needs a
 * live crossing, not a mock.
 *
 * FAILS LOUDLY when any CS_* env var is missing, matching `roundtrip.test.ts`.
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

function requireEnv(): Record<(typeof REQUIRED_ENV)[number], string> {
  const values = {} as Record<(typeof REQUIRED_ENV)[number], string>
  const missing: string[] = []
  for (const key of REQUIRED_ENV) {
    const value = Deno.env.get(key)
    if (value) values[key] = value
    else missing.push(key)
  }
  if (missing.length > 0) {
    // FAIL, don't skip: a silently-skipped credential suite reads as green
    // coverage that never ran (same doctrine as the repo's integration
    // harness — no skipIf credential gates).
    throw new Error(
      `Missing required env: ${missing.join(', ')}. This suite needs real ` +
        'CipherStash credentials — export the four CS_* variables (or put them ' +
        'in a repo-root .env; see AGENTS.md "Environment variables") or run ' +
        'via the CI job, which injects them.',
    )
  }
  return values
}

const catalog = encryptedTable('wasm_query_matrix', {
  email: types.TextEq('email'), // equality only
  bio: types.TextSearch('bio'), // free-text (also carries eq + ore)
  age: types.IntegerOrd('age'), // eq + order/range
  prefs: types.Json('prefs'), // searchable JSON (ste_vec)
})

/** A v3 SCALAR query term: versioned envelope (`v: 3`), NO ciphertext. */
function assertV3Term(term: unknown, label: string) {
  assertExists(term, `${label}: encryptQuery returned null`)
  const obj = term as Record<string, unknown>
  assertEquals(obj.v, 3, `${label}: term is not EQL v3`)
  assertEquals('c' in obj, false, `${label}: term carries ciphertext`)
}

/** A v3 JSON CONTAINMENT needle: strict `{sv: [query-entry]}` — no `v`
 * envelope, no ciphertext (per `is_valid_ste_vec_query_payload`). */
function assertContainmentNeedle(term: unknown, label: string) {
  assertExists(term, `${label}: encryptQuery returned null`)
  const obj = term as Record<string, unknown>
  assertEquals(
    Array.isArray(obj.sv),
    true,
    `${label}: expected an {sv: [...]} containment needle`,
  )
  assertEquals('c' in obj, false, `${label}: needle carries ciphertext`)
}

Deno.test({
  name: 'stack/wasm-inline: encryptQuery covers every v3 query type',
  permissions: {
    env: true,
    net: true,
    read: true,
    sys: true,
    // No FFI permission, same pin as roundtrip.test.ts: if protect-ffi ever
    // silently fell back to a native binding under Deno, the call would
    // reject — so a green run proves the WASM path minted every term.
    ffi: false,
  },
  async fn() {
    const env = requireEnv()
    const client = await Encryption({
      schemas: [catalog],
      config: {
        workspaceCrn: env.CS_WORKSPACE_CRN,
        accessKey: env.CS_CLIENT_ACCESS_KEY,
        clientId: env.CS_CLIENT_ID,
        clientKey: env.CS_CLIENT_KEY,
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

    // searchableJson, string value → ste_vec_selector (JSONPath). By
    // contract the selector "term" is a BARE selector-hash string — no
    // envelope — bound as the text argument of `->` / `->>`.
    const selector = await client.encryptQuery('$.theme', {
      table: catalog,
      column: catalog.prefs,
      queryType: 'searchableJson',
    })
    assertExists(selector, 'selector: encryptQuery returned null')
    assertEquals(
      typeof selector,
      'string',
      'selector: expected the bare selector-hash string',
    )
    assertEquals(
      (selector as unknown as string).length > 0,
      true,
      'selector: empty selector hash',
    )

    // searchableJson, object value → ste_vec_term (containment needle:
    // strict {sv: [...]}, no version envelope — per the eql_v3.query_jsonb
    // wire contract)
    assertContainmentNeedle(
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
        value: null,
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
    assertContainmentNeedle(bulk[4], 'bulk/searchableJson')
  },
})
