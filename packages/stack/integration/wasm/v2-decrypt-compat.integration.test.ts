/**
 * WASM v2 read compatibility (#815 review).
 *
 * The native entry's equivalent lives in `integration/shared/`. This is the
 * edge/serverless half of the same obligation: a customer on Deno, Bun,
 * Cloudflare Workers or Supabase Edge Functions with rows written before the v3
 * migration must still be able to read them.
 *
 * The pairing used to be refused outright by `encryptedDynamoDB` on the belief
 * that the WASM entry could not serve a legacy read. It can: both bindings are
 * builds of the same protect-ffi crate, whose `decrypt` accepts either wire
 * generation regardless of the client's `eqlVersion`. This suite is the
 * executable proof of that claim — the refusal was lifted on its strength.
 *
 * Fixtures are minted directly with protect-ffi in EQL v2 mode, exactly as the
 * shared suite does: production callers cannot select v2 writes on either entry.
 *
 * The shared suite's second block — v2 payloads read through a client that never
 * registered their table — is mirrored here by ONE case, deliberately narrow.
 * The invariant it protects (decrypt is payload-shape-driven and never consults
 * the encrypt config) is enforced in two places, and only one of them is shared
 * between the entries: the field-selection helpers are the same TypeScript on
 * both, but `decrypt` itself is a separate compiled artifact per binding. So the
 * native suite proving the native binding ignores its `encryptConfig` says
 * nothing about the WASM one, and that gap is what the case below closes.
 *
 * The rest of the shared block is not duplicated on purpose. Its DynamoDB case
 * exercises the `storedEqlVersion: 2` early return in
 * `assertClientTableVersionMatch`, which is entry-agnostic TypeScript already
 * covered there; re-running it against the WASM client would re-test the same
 * branch rather than the WASM binding. Nor is there a `getEncryptConfig()`
 * precondition here — this entry's client does not expose one, and the client is
 * constructed from `schemas: [unrelated]` a few lines below with nothing merging
 * into it.
 *
 * The second describe block below is about TYPES rather than surfaces, and it is
 * NOT a transcription of the shared suite's matrix — see its own header for why
 * per-type reconstruction has to be proven separately on this entry.
 */
import type { JsPlaintext } from '@cipherstash/protect-ffi'
import {
  encrypt as ffiEncrypt,
  encryptBulk as ffiEncryptBulk,
  newClient as newFfiClient,
} from '@cipherstash/protect-ffi'
import {
  unwrapResult,
  v2FixtureColumns,
  v2FixturePlan,
  v2ModelRows,
} from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toEncryptedDynamoItem } from '@/dynamodb/helpers'
import { buildEncryptConfig, encryptedTable, types } from '@/eql/v3'
import type { CastAs } from '@/schema'
import type { Encrypted } from '@/types'
import { Encryption as WasmEncryption } from '@/wasm-inline'

const users = encryptedTable('wasm_v2_read_compat_users', {
  email: types.TextEq('email'),
})

/**
 * A DIFFERENT table, sharing no name or column with `users`, so `unrelatedClient`
 * below has never heard of `wasm_v2_read_compat_users`. See the header for why
 * that unregistered read is the case worth carrying onto this entry.
 */
const unrelated = encryptedTable('wasm_v2_read_compat_unrelated_v3', {
  note: types.TextEq('note'),
})

const SECRET = 'ada@example.com'
let fixtureClient: Awaited<ReturnType<typeof newFfiClient>>
let client: Awaited<ReturnType<typeof WasmEncryption>>
let unrelatedClient: Awaited<ReturnType<typeof WasmEncryption>>

/**
 * The WASM factory hard-requires explicit credentials — no dev-profile
 * fallback (#663) — so read them straight from the environment. The
 * integration harness has already asserted they exist.
 */
const wasmCredentials = () => ({
  workspaceCrn: process.env.CS_WORKSPACE_CRN as string,
  accessKey: process.env.CS_CLIENT_ACCESS_KEY as string,
  clientId: process.env.CS_CLIENT_ID as string,
  clientKey: process.env.CS_CLIENT_KEY as string,
})

beforeAll(async () => {
  fixtureClient = await newFfiClient({
    encryptConfig: buildEncryptConfig(users),
    eqlVersion: 2,
  })
  client = await WasmEncryption({
    schemas: [users],
    config: wasmCredentials(),
  })
  unrelatedClient = await WasmEncryption({
    schemas: [unrelated],
    config: wasmCredentials(),
  })
})

async function v2Ciphertext(value: string): Promise<Encrypted> {
  return (await ffiEncrypt(fixtureClient, {
    plaintext: value,
    table: users.tableName,
    column: users.email.getName(),
  })) as Encrypted
}

describe('wasm-inline v3 client reads stored EQL v2 payloads', () => {
  it('decrypts a scalar ciphertext', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    expect(encrypted).toMatchObject({ v: 2 })

    expect(unwrapResult(await client.decrypt(encrypted))).toBe(SECRET)
  }, 30000)

  it('decrypts a DynamoDB item reconstructed as stored EQL v2', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    const stored = toEncryptedDynamoItem({ pk: 'a', email: encrypted }, [
      'email',
    ])
    const dynamo = encryptedDynamoDB({ encryptionClient: client })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(stored, users, { storedEqlVersion: 2 }),
    )
    expect(decrypted).toMatchObject({ pk: 'a', email: SECRET })
  }, 30000)

  /**
   * Keep this reading through `unrelatedClient`. Pointed back at `client` it
   * becomes a duplicate of the first case, green forever, and the WASM binding's
   * half of the payload-shape-driven invariant goes uncovered.
   */
  it('decrypts a ciphertext for a table this client never registered', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    // Guard against a false pass: genuinely v2 wire, and naming the table the
    // reading client was not built with.
    expect(encrypted).toMatchObject({
      v: 2,
      i: { t: users.tableName, c: 'email' },
    })

    expect(unwrapResult(await unrelatedClient.decrypt(encrypted))).toBe(SECRET)
  }, 30000)
})

/**
 * The TYPE axis of the same obligation. Everything above reads v2 payloads out
 * of a single `types.TextEq` column, so it proves the SURFACES this entry has
 * (scalar / DynamoDB item / unregistered table) and nothing about what happens
 * to a `date`, a `bigint` or a `boolean` on the way back.
 *
 * This is NOT a transcription of the shared suite's matrix, and the reason is
 * the whole point of carrying it here: per-type reconstruction is a SEPARATE
 * implementation on each entry.
 *
 *  - Native rebuilds the whole row at once — `rowReconstructor` calls
 *    `reconstructDatePaths(row, paths)` (`src/encryption/client-v3.ts`), which
 *    walks dotted paths and clones intermediates.
 *  - This entry rebuilds ONE VALUE AT A TIME, inside the batch rebuild loop of
 *    `decryptModelsBatch` (`src/wasm-inline.ts`):
 *    `dateFields.has(field.fieldKey) ? reconstructDateValue(item.data) : item.data`,
 *    against a per-table `Set` of JS property names that `datePropertyPaths`
 *    precomputes at construction.
 *
 * The two share `DATE_LIKE_CASTS` (`src/eql/v3/columns.ts`) — the table of WHICH
 * casts are date-like — and nothing else. The code that acts on it differs, so
 * the native matrix going green says nothing about this path.
 *
 * `bigint` is the other axis that cannot be inherited from the native run, and
 * here it is sharper: on this entry a bigint crosses the wasm-bindgen serde
 * boundary as a `js_sys::BigInt` built by protect-ffi's `encode_plaintext` (see
 * {@link import('@/wasm-inline').WasmPlaintext}), not as a NAPI value.
 * `PlaintextFromKind` promises `bigint` and `V3DecryptedModel` propagates it, so
 * the TYPE says `bigint` even on a legacy read. Asserted with an explicit
 * `typeof`, not a loose equality: if a v2 payload comes back as a string, that is
 * a product defect and this must fail rather than quietly accept it.
 *
 * Reads go through the MODEL path deliberately. It is the only path with a table
 * to resolve `cast_as` from, and therefore the only one that reconstructs
 * anything at all; the last two cases pin the single-value boundaries rather
 * than hiding them.
 *
 * The live work is BATCHED exactly as the native matrix batches it: one mega
 * table spanning every mintable domain, one `encryptBulk` to mint the whole
 * fixture set, one `bulkDecryptModels` to read it back — not ~100 sequential
 * round trips.
 *
 * Domain SELECTION comes from `@cipherstash/test-kit`'s `v2FixturePlan()`, the
 * same plan the native suite drives, so the two entries cannot quietly disagree
 * about which domains they claim to cover. Exclusions are declared there with a
 * written reason (ope-indexed domains have no v2 wire representation; no v2
 * `ste_vec` fixture can be minted at all with cipherstash-client 0.42).
 *
 * The plan's ACCOUNTING checks — every catalog domain either minted or deferred,
 * the deferral list matching its own written rationale, no plaintext axis lost
 * without being declared — are deliberately NOT repeated here. They are pure
 * functions over `V3_MATRIX` with no entry, no FFI and no network in them, and
 * they already run creds-free for every contributor in
 * `__tests__/test-kit-v2-fixtures.test.ts`. A third copy inside a suite that
 * only collects with live credentials would fire for fewer people, not more.
 */
const matrixPlan = v2FixturePlan()
const matrix = encryptedTable(
  'wasm_v2_read_compat_matrix',
  v2FixtureColumns(matrixPlan),
)

// Flattened to one assertion per (domain, sample), labelled so vitest names the
// exact domain and sample index that failed.
const matrixCases = matrixPlan.cases.map(
  (fixture) =>
    [
      fixture.label,
      fixture.slug,
      fixture.castAs,
      fixture.sample,
      fixture.row,
    ] as const,
)

/**
 * Assert a decrypted field against its catalog sample, keyed by the plaintext
 * axis rather than by `typeof sample`, so the runtime SHAPE is pinned and not
 * merely the value.
 *
 * A near-twin of the native suite's helper, and kept local on purpose: the two
 * entries are exactly what this file exists to tell apart, so a shared assertion
 * that drifted to accommodate one of them would silently weaken the other. (If
 * it is ever hoisted, `@cipherstash/test-kit` is its home — beside the plan it
 * asserts against — not an import across two integration suites.)
 *
 * The `default` arm throws instead of falling back to a loose comparison: a
 * catalog domain on a new `cast_as` must arrive with a deliberate assertion, not
 * inherit a weak one and look covered.
 */
function expectReconstructed(
  actual: unknown,
  castAs: CastAs,
  sample: unknown,
  label: string,
): void {
  switch (castAs) {
    case 'date':
    case 'timestamp':
      // `reconstructDateValue` must have run off the v3 table's cast_as even
      // though the payload on the wire was v2.
      expect(actual, `${label}: expected a reconstructed Date`).toBeInstanceOf(
        Date,
      )
      expect(actual).toEqual(sample)
      return
    case 'bigint':
      // Not `toEqual`: a string "42" and 42n compare unequal under toBe, but the
      // point is the TYPE, and only an explicit typeof states it.
      expect(typeof actual, `${label}: expected a native bigint`).toBe('bigint')
      expect(actual).toBe(sample)
      return
    case 'number':
      expect(typeof actual, `${label}: expected a number`).toBe('number')
      expect(actual).toBe(sample)
      return
    case 'string':
      expect(typeof actual, `${label}: expected a string`).toBe('string')
      expect(actual).toBe(sample)
      return
    case 'boolean':
      expect(typeof actual, `${label}: expected a boolean`).toBe('boolean')
      expect(actual).toBe(sample)
      return
    default:
      throw new Error(
        `${label}: no reconstruction assertion for cast_as "${castAs}". ` +
          'Add one rather than letting a new plaintext axis pass unchecked.',
      )
  }
}

describe('a wasm-inline client reconstructs every plaintext axis from stored EQL v2 payloads', () => {
  let matrixFixtureClient: Awaited<ReturnType<typeof newFfiClient>>
  let matrixClient: Awaited<ReturnType<typeof WasmEncryption>>
  let encrypted: Array<Record<string, Encrypted>>
  let decrypted: Array<Record<string, unknown>>
  let singleRow: Record<string, unknown>

  beforeAll(async () => {
    // Fixtures are minted through the NATIVE binding in v2 mode on both entries,
    // and that is not a shortcut: this entry hardcodes `eqlVersion: 3` in its
    // factory (`src/wasm-inline.ts`) and rejects the config key outright, so it
    // cannot mint its own legacy fixture even in a test. The wire generation is
    // a property of the payload, not of the client that reads it — which is the
    // claim the whole file exists to prove — and every case below re-checks
    // `v: 2` on the bytes it actually asserts against.
    matrixFixtureClient = await newFfiClient({
      encryptConfig: buildEncryptConfig(matrix),
      eqlVersion: 2,
    })
    matrixClient = await WasmEncryption({
      schemas: [matrix],
      config: wasmCredentials(),
    })

    // One network call for the whole matrix. `encryptBulk` correlates results
    // POSITIONALLY (its payload type carries no id), which is why every case
    // below re-checks the identifier it got back.
    const payloads = (await ffiEncryptBulk(matrixFixtureClient, {
      plaintexts: matrixPlan.cases.map((fixture) => ({
        plaintext: fixture.plaintext as JsPlaintext,
        table: matrix.tableName,
        column: fixture.slug,
      })),
    })) as Encrypted[]

    encrypted = v2ModelRows(matrixPlan, payloads)
    // The table argument is REQUIRED on this entry — `requiresTableForDecrypt`
    // — and it is also what supplies the date paths, so the reconstruction
    // under test only happens because `matrix` is registered on the client.
    decrypted = unwrapResult(
      await matrixClient.bulkDecryptModels(encrypted, matrix),
    )
    singleRow = unwrapResult(
      await matrixClient.decryptModel(encrypted[0], matrix),
    )
  }, 60000)

  it.each(
    matrixCases,
  )('%s decrypts from a stored EQL v2 payload through the wasm model path', (label, slug, castAs, sample, row) => {
    const payload = encrypted[row][slug]

    // THE guard for this block. Without it the whole matrix would pass just as
    // happily against v3 fixtures and prove nothing about legacy reads. The
    // identifier is checked too: `encryptBulk` correlates positionally, so a
    // mis-zipped batch could otherwise assert one domain's sample against
    // another domain's ciphertext and go green by coincidence.
    expect(payload).toMatchObject({
      v: 2,
      i: { t: matrix.tableName, c: slug },
    })
    expect(payload).toHaveProperty('c')

    expectReconstructed(decrypted[row][slug], castAs, sample, label)
  })

  /**
   * `decryptModel` and `bulkDecryptModels` are separate wrappers over
   * `decryptModelsBatch`, and only the bulk one is exercised above. A row's
   * worth of domains through the single path catches the wrapper being wired up
   * without its per-model destructure.
   */
  it('reconstructs the same values on the single-model decrypt path', () => {
    const firstRow = matrixPlan.cases.filter((fixture) => fixture.row === 0)
    expect(firstRow.length).toBe(matrixPlan.domains.length)
    for (const fixture of firstRow) {
      expectReconstructed(
        singleRow[fixture.slug],
        fixture.castAs,
        fixture.sample,
        `${fixture.label} (single model)`,
      )
    }
  })

  /**
   * The boundary, pinned rather than asserted away: date reconstruction is a
   * property of the MODEL path, which has a table to read `cast_as` from. This
   * entry's single-value `decrypt` takes no table, so it returns the stored
   * string — the same contract v3 has here, and the reason the matrix above
   * reads through models.
   *
   * Compared as an instant rather than a literal string: the wire form of a
   * `date` plaintext is the FFI's business, and pinning it here would fail on a
   * cosmetic change while saying nothing about the contract.
   */
  it('returns a date-like scalar as its stored string, not a Date', async () => {
    const dateCase = matrixPlan.cases.find(
      (fixture) => fixture.castAs === 'date',
    )
    if (!dateCase) {
      throw new Error(
        'the catalog no longer has a mintable `date` domain to pin this boundary with',
      )
    }

    const payload = encrypted[dateCase.row][dateCase.slug]
    expect(payload).toMatchObject({ v: 2 })

    const value = unwrapResult(await matrixClient.decrypt(payload))
    expect(value).not.toBeInstanceOf(Date)
    expect(typeof value).toBe('string')
    expect(new Date(String(value))).toEqual(dateCase.sample)
  }, 30000)

  /**
   * The one extra single-value read this block spends a round trip on, and the
   * contrast with the case above is the reason.
   *
   * A `Date` is reconstructed by SDK TypeScript, so the scalar path returning a
   * string is a boundary. A `bigint` is not: nothing in this SDK converts it —
   * it is built inside the WASM module by protect-ffi's `encode_plaintext` and
   * handed out as-is. So `bigint` must survive the SCALAR path too, and the
   * scalar path is a different wasm-bindgen export from the batch one
   * (`decrypt` vs `decryptBulkFallible`) with its own serde crossing. The matrix
   * above only exercises the batch export.
   */
  it('returns a native bigint from a v2 payload on the scalar path', async () => {
    const bigintCase = matrixPlan.cases.find(
      (fixture) => fixture.castAs === 'bigint',
    )
    if (!bigintCase) {
      throw new Error(
        'the catalog no longer has a mintable `bigint` domain to pin this contract with',
      )
    }

    const payload = encrypted[bigintCase.row][bigintCase.slug]
    expect(payload).toMatchObject({ v: 2 })

    const value = unwrapResult(await matrixClient.decrypt(payload))
    expect(
      typeof value,
      'wasm scalar decrypt must return a native bigint',
    ).toBe('bigint')
    expect(value).toBe(bigintCase.sample)
  }, 30000)
})
