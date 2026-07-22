/**
 * WASM smoke test for `@cipherstash/stack/wasm-inline`.
 *
 * Runs under Deno against real CipherStash credentials. Proves four things
 * together:
 *   1. The stack `/wasm-inline` subpath resolves under Deno (no native
 *      binding required).
 *   2. The entry is EQL v3: a schema authored with the `types` DSL round-trips.
 *      `TextSearch` maps to the concrete `eql_v3_text_search` domain, which a
 *      v2-mode client cannot resolve — so a successful round-trip proves the
 *      factory pinned `eqlVersion: 3` (#614).
 *   3. The WASM protect-ffi client completes an encrypt → decrypt round-trip
 *      against ZeroKMS / CTS.
 *   4. No FFI permission was granted to the Deno process, so the WASM path is
 *      the *only* path that could have succeeded.
 *
 * FAILS LOUDLY when any CS_* env var is missing — a silently-skipped
 * credential suite reads as green coverage that never ran.
 */

import { assertEquals, assertExists } from 'jsr:@std/assert@^1.0.0'
import {
  Encryption,
  encryptedTable,
  isEncrypted,
  types,
} from '@cipherstash/stack/wasm-inline'

// `CS_WORKSPACE_CRN` is the single source of truth for workspace
// identity and region — the stack `/wasm-inline` config requires it and
// derives the `AccessKeyStrategy` region from it. `CS_REGION` is not
// consulted.
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

Deno.test({
  name: 'stack/wasm-inline: EQL v3 encrypt → decrypt round-trip via WASM',
  permissions: {
    env: true,
    net: true,
    read: true,
    sys: true,
    // No FFI permission. If protect-ffi ever silently tries a native
    // binding under Deno, the call will reject — proving WASM took the
    // request.
    ffi: false,
  },
  async fn() {
    const env = requireEnv()

    // Sanity: we really are in Deno, and WASM is available.
    assertExists(globalThis.WebAssembly, 'WebAssembly global missing')
    assertExists(
      globalThis.Deno,
      'Deno global missing (test framework misconfigured)',
    )

    // A v3 table authored with the `types` DSL re-exported from `/wasm-inline`.
    // `TextSearch` maps to `eql_v3_text_search`, which only a v3-mode client
    // can resolve — so this round-trip proves the factory selected eqlVersion 3.
    const users = encryptedTable('protect-ci', {
      email: types.TextSearch('email'),
    })

    const client = await Encryption({
      schemas: [users],
      config: {
        // CRN is the single source of truth — the region the
        // AccessKeyStrategy needs is derived from it.
        workspaceCrn: env.CS_WORKSPACE_CRN,
        accessKey: env.CS_CLIENT_ACCESS_KEY,
        clientId: env.CS_CLIENT_ID,
        clientKey: env.CS_CLIENT_KEY,
      },
    })

    const plaintext = `wasm-v3-smoke-${crypto.randomUUID()}@example.com`

    // Every fallible method returns `{ data } | { failure }` (#741). Unwrap
    // at each boundary — passing an envelope on would fail in ways that look
    // like an encryption bug rather than a plumbing one.
    const encryptResult = await client.encrypt(plaintext, {
      column: users.email,
      table: users,
    })
    assertEquals(
      encryptResult.failure,
      undefined,
      `encrypt() failed: ${encryptResult.failure?.message}`,
    )
    const encrypted = encryptResult.data

    assertEquals(
      isEncrypted(encrypted),
      true,
      'encrypt() did not return a recognised EQL payload',
    )

    // The storage payload must survive `JSON.stringify` as a v3 envelope —
    // this is the exact wire crossing every SQL insert performs, and
    // `isEncrypted` alone cannot pin it: the wasm boundary deserializes JS
    // `Map`s just as happily as plain objects, so a payload that stringifies
    // to `{}` would still round-trip through decrypt above.
    const envelope = encrypted as Record<string, unknown>
    assertEquals(
      envelope?.v,
      3,
      `storage payload is not a v3 envelope via property access — typeof=${typeof encrypted}, ` +
        `ctor=${(encrypted as object)?.constructor?.name}, ` +
        `keys=[${Object.keys(envelope ?? {}).join(', ')}]`,
    )
    const wire = JSON.parse(JSON.stringify(encrypted)) as Record<
      string,
      unknown
    >
    for (const key of ['v', 'i', 'c'] as const) {
      assertExists(
        wire[key],
        `storage payload lost "${key}" across JSON.stringify — wire keys=[${Object.keys(wire).join(', ')}]`,
      )
    }
    assertEquals(String(wire.v), '3', 'wire envelope is not v3')

    const decryptResult = await client.decrypt(encrypted)
    assertEquals(
      decryptResult.failure,
      undefined,
      `decrypt() failed: ${decryptResult.failure?.message}`,
    )
    assertEquals(decryptResult.data, plaintext, 'round-trip plaintext mismatch')

    // 5. (#662) Searchable encryption is reachable on the edge: mint a v3
    //    QUERY TERM for the column's free-text index. Terms are
    //    ciphertext-free needles — assert the wire shape, not decryption.
    const termResult = await client.encryptQuery(plaintext, {
      column: users.email,
      table: users,
      queryType: 'freeTextSearch',
    })
    assertEquals(
      termResult.failure,
      undefined,
      `encryptQuery() failed: ${termResult.failure?.message}`,
    )
    const term = termResult.data as Record<string, unknown> | null
    assertExists(term, 'encryptQuery() returned null for live plaintext')
    assertEquals(term.v, 3, 'query term is not EQL v3')
    assertEquals(
      'c' in term,
      false,
      'query term unexpectedly carries ciphertext',
    )

    // Bulk form is position-stable, nulls pass through.
    const bulkResult = await client.encryptQueryBulk([
      { value: plaintext, column: users.email, table: users },
      { value: null, column: users.email, table: users },
    ])
    assertEquals(
      bulkResult.failure,
      undefined,
      `encryptQueryBulk() failed: ${bulkResult.failure?.message}`,
    )
    const bulk = bulkResult.data
    assertEquals(bulk.length, 2)
    assertExists(bulk[0])
    assertEquals(bulk[1], null)

    // 6. (#741) The value-level bulk ops — the whole reason a list read on the
    //    edge is one ZeroKMS round trip instead of N. Nothing else in the repo
    //    exercises these against real ZeroKMS.
    const second = `wasm-v3-bulk-${crypto.randomUUID()}@example.com`
    const bulkEncrypted = await client.bulkEncrypt([
      { plaintext, column: users.email, table: users },
      { plaintext: null, column: users.email, table: users },
      { plaintext: second, column: users.email, table: users },
    ])
    assertEquals(
      bulkEncrypted.failure,
      undefined,
      `bulkEncrypt() failed: ${bulkEncrypted.failure?.message}`,
    )
    const payloads = bulkEncrypted.data
    assertEquals(payloads.length, 3, 'bulkEncrypt is not index-aligned')
    assertEquals(payloads[1], null, 'null plaintext did not yield null')
    assertExists(payloads[0])
    assertExists(payloads[2])
    assertEquals(isEncrypted(payloads[0]), true, 'bulkEncrypt[0] not a payload')

    const bulkDecrypted = await client.bulkDecrypt(payloads)
    assertEquals(
      bulkDecrypted.failure,
      undefined,
      `bulkDecrypt() failed: ${bulkDecrypted.failure?.message}`,
    )
    // Round-trips at the ORIGINAL indices, with the null hole preserved.
    assertEquals(bulkDecrypted.data, [plaintext, null, second])

    // 7. (#742) The model helpers — the surface that walks a model against
    //    its schema, so edge code never hand-rolls the field mapping whose
    //    failure mode is a column silently persisted in plaintext. Each call
    //    is one ZeroKMS round trip regardless of field or model count.
    const rowA = { id: 'row-a', email: plaintext, note: null }
    const modelResult = await client.encryptModel(rowA, users)
    assertEquals(
      modelResult.failure,
      undefined,
      `encryptModel() failed: ${modelResult.failure?.message}`,
    )
    const encryptedRow = modelResult.data
    assertEquals(encryptedRow.id, 'row-a', 'passthrough field was altered')
    assertEquals(encryptedRow.note, null, 'null field was altered')
    assertEquals(
      isEncrypted(encryptedRow.email),
      true,
      'schema field was not encrypted by encryptModel',
    )

    const modelBack = await client.decryptModel(encryptedRow, users)
    assertEquals(
      modelBack.failure,
      undefined,
      `decryptModel() failed: ${modelBack.failure?.message}`,
    )
    assertEquals(modelBack.data, rowA, 'model round-trip mismatch')

    const rowB = { id: 'row-b', email: second, note: 'kept' }
    const bulkModels = await client.bulkEncryptModels([rowA, rowB], users)
    assertEquals(
      bulkModels.failure,
      undefined,
      `bulkEncryptModels() failed: ${bulkModels.failure?.message}`,
    )
    assertEquals(bulkModels.data.length, 2, 'bulkEncryptModels misaligned')

    const bulkModelsBack = await client.bulkDecryptModels(
      bulkModels.data,
      users,
    )
    assertEquals(
      bulkModelsBack.failure,
      undefined,
      `bulkDecryptModels() failed: ${bulkModelsBack.failure?.message}`,
    )
    assertEquals(
      bulkModelsBack.data,
      [rowA, rowB],
      'bulk model round-trip mismatch',
    )
  },
})
