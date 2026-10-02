/**
 * Legacy DynamoDB reads (`storedEqlVersion: 2`) across the TYPE catalog.
 *
 * `v2-table-forwarding.test.ts` covers the SURFACE axis of this path — which
 * table is forwarded, to which client shape, on single vs. bulk reads — and
 * every case there uses one `types.TextEq` column. That leaves the question this
 * file exists to answer untouched: what happens to a `date`, a `bigint`, a
 * `boolean` or a nested column on the way back out of a legacy read.
 *
 * The question is not cosmetic, because the two halves of a legacy read disagree
 * about wire version by design:
 *
 *  - the ENVELOPE is rebuilt as v2 (`{ v: 2, k: 'ct', i, c }`) from the stored
 *    `<attr>__source` — `toItemWithEqlPayloads` with a v2 read context;
 *  - the RECONSTRUCTION is driven by the CURRENT v3 descriptor's `cast_as`
 *    (`DATE_LIKE_CASTS` → `rowReconstructor` → `reconstructDatePaths`) and runs
 *    regardless of what the payload said on the wire.
 *
 * ## What is faked, and why that still proves something
 *
 * The seam is cut at the protect-ffi boundary and nowhere above it. `ffiStub`
 * stands in for the native client that talks to the FFI; it is wrapped by the
 * REAL `createEncryptionClient`, and read through the REAL `encryptedDynamoDB`.
 * So the envelope rebuild, the table forwarding, the registration check and the
 * date reconstruction are all product code — only the crypto is stubbed.
 *
 * Each case therefore asserts at BOTH ends, and the two ends are different
 * values, so no case can pass by echoing its own fixture:
 *
 *  - the envelope handed DOWN to the stub is compared against the exact v2
 *    payload the adapter is supposed to have rebuilt (opaque ciphertext token
 *    included), and
 *  - the model handed BACK UP is compared against the catalog's `sample` — while
 *    the stub only ever returns the catalog's `plaintext`, which for every
 *    date-like domain is an ISO STRING. A `Date` in the result can only have
 *    come from real reconstruction.
 *
 * The honest limit: this cannot say what protect-ffi returns for a v2 payload of
 * a given domain — that is what
 * `integration/shared/v2-decrypt-compat.integration.test.ts` mints real v2
 * fixtures to answer. What it can say, and does, is that everything between the
 * FFI and the caller carries those plaintexts faithfully and reconstructs the
 * date-like ones. See `bigint is carried, never repaired` below, which pins the
 * consequence of that split rather than papering over it.
 *
 * Domain SELECTION comes from `@cipherstash/test-kit`'s `v2FixturePlan()` — the
 * same plan the native and WASM v2 suites use, so the three surfaces cannot
 * quietly disagree about which domains they claim. Its accounting (every catalog
 * domain minted or deferred with a written reason) is asserted in
 * `__tests__/test-kit-v2-fixtures.test.ts` and not repeated here.
 */
import type { V2FixtureCase } from '@cipherstash/test-kit'
import {
  unwrapResult,
  v2FixtureColumns,
  v2FixturePlan,
} from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { createEncryptionClient } from '@/encryption/client-v3'
import {
  type AnyV3Table,
  buildEncryptConfig,
  encryptedTable,
  types,
} from '@/eql/v3'
import type { CastAs } from '@/schema'

// ---------------------------------------------------------------------------
// The seam: a stub at the protect-ffi boundary, wrapped by the real client.
// ---------------------------------------------------------------------------

/** The parameter `createEncryptionClient` wraps. Its type is not exported. */
type UnderlyingClient = Parameters<typeof createEncryptionClient>[0]

/**
 * A minimal operation stub. `createEncryptionClient` wraps the underlying
 * decrypt op in a `MappedDecryptOperation` and calls `.execute()` on it, so the
 * stub must be operation-like rather than a bare promise — the same shape
 * `typed-client-v3.test.ts` uses.
 */
function fakeOp<R>(result: R) {
  return {
    execute: () => Promise.resolve(result),
    audit() {
      return this
    },
    withLockContext() {
      return this
    },
  }
}

/**
 * Stand in for the native client that calls protect-ffi.
 *
 * `wire` maps a fake ciphertext to the plaintext protect-ffi would hand back for
 * it. Selection is STRUCTURAL — `v` + `i` + (`c` | `sv`) — which is how the FFI
 * itself discriminates an encrypted field. The predicate is restated here rather
 * than imported from `@/encryption/helpers` so the stub is an independent
 * oracle: importing the product's detector would let a regression in it pass
 * unnoticed on both sides at once.
 *
 * A ciphertext with no fixture THROWS. The adapter runs this inside
 * `withResult`, so it surfaces as a `{ failure }` naming the envelope — which is
 * what a case sees if the adapter ever stops rebuilding one.
 */
function ffiStub(options: {
  wire: Record<string, unknown>
  tables: readonly AnyV3Table[]
}) {
  /** Models handed DOWN to the FFI boundary, in call order. */
  const received: Array<Record<string, unknown>> = []

  const decryptTree = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(decryptTree)
    if (value === null || typeof value !== 'object') return value

    const payload = value as Record<string, unknown>
    const isEnvelope =
      typeof payload.v === 'number' &&
      typeof payload.i === 'object' &&
      payload.i !== null &&
      ('c' in payload || 'sv' in payload)

    if (isEnvelope) {
      // Scalars are keyed by their ciphertext; a SteVec document has no root
      // `c`, so its per-document KeyHeader `h` is the handle instead.
      const handle =
        typeof payload.c === 'string'
          ? payload.c
          : typeof payload.h === 'string'
            ? payload.h
            : undefined
      if (handle === undefined || !(handle in options.wire)) {
        throw new Error(
          `[ffi stub]: no fixture plaintext for envelope ${JSON.stringify(payload)}`,
        )
      }
      return options.wire[handle]
    }

    return Object.fromEntries(
      Object.entries(payload).map(([key, nested]) => [
        key,
        decryptTree(nested),
      ]),
    )
  }

  const underlying = {
    decryptModel: (input: Record<string, unknown>) => {
      received.push(input)
      return fakeOp({ data: decryptTree(input) })
    },
    bulkDecryptModels: (input: Array<Record<string, unknown>>) => {
      received.push(...input)
      return fakeOp({ data: input.map(decryptTree) })
    },
    // The adapter's v3 registration guard reads this off the client. Returning a
    // real config (rather than `undefined`, which the guard treats as unreadable
    // and stays silent on) is what makes the v3-vs-v2 contrast below meaningful.
    getEncryptConfig: () => buildEncryptConfig(...options.tables),
  }

  const client = createEncryptionClient(
    underlying as unknown as UnderlyingClient,
    ...options.tables,
  )

  return {
    received,
    client,
    dynamo: encryptedDynamoDB({ encryptionClient: client }),
  }
}

/**
 * Assert a decrypted field against its catalog sample, keyed by the plaintext
 * axis rather than by `typeof sample`, so the runtime SHAPE is pinned and not
 * merely the value. Mirrors the helper in the native v2 integration suite.
 *
 * The `default` arm throws instead of comparing loosely: a catalog domain on a
 * new `cast_as` must arrive with a deliberate assertion, not inherit a weak one
 * and look covered.
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
      // The stub returns an ISO STRING for these, so a `Date` here can only be
      // the v3 descriptor's `cast_as` driving `reconstructDatePaths` over a
      // payload that was v2 on the wire.
      expect(actual, `${label}: expected a reconstructed Date`).toBeInstanceOf(
        Date,
      )
      expect(actual).toEqual(sample)
      return
    case 'bigint':
      // Not `toEqual`: the point is the TYPE, and only an explicit typeof states
      // it. `V3DecryptedModel` promises `bigint` on a legacy read too.
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

// ---------------------------------------------------------------------------
// The domain matrix
// ---------------------------------------------------------------------------

const plan = v2FixturePlan()
const matrix = encryptedTable('v2_dynamodb_matrix', v2FixtureColumns(plan))

/** The opaque `<attr>__source` value a legacy item holds for this fixture. */
const ciphertext = (fixture: Pick<V2FixtureCase, 'slug' | 'row'>) =>
  `ct:${fixture.slug}#${fixture.row}`

/** Which domains stored a `<attr>__hmac` alongside the ciphertext. */
const hasSearchTerm = new Map(
  plan.domains.map((domain) => [
    domain.slug,
    domain.spec.indexes?.unique !== undefined,
  ]),
)

/**
 * The stored items, as DynamoDB holds them: split attributes only, never an
 * envelope. `pk` and `note` are undeclared attributes that must survive the read
 * untouched.
 */
const storedRows = Array.from({ length: plan.rowCount }, (_, row) => {
  const item: Record<string, unknown> = {
    pk: `item#${row}`,
    note: 'passthrough',
  }
  for (const fixture of plan.cases) {
    if (fixture.row !== row) continue
    item[`${fixture.slug}__source`] = ciphertext(fixture)
    if (hasSearchTerm.get(fixture.slug)) {
      item[`${fixture.slug}__hmac`] = `hmac:${fixture.slug}#${row}`
    }
  }
  return item
})

const wire = Object.fromEntries(
  plan.cases.map((fixture) => [ciphertext(fixture), fixture.plaintext]),
)

// Flattened to one assertion per (domain, sample), labelled so vitest names the
// exact domain and sample index that failed.
const matrixCases = plan.cases.map(
  (fixture) =>
    [
      fixture.label,
      fixture.slug,
      fixture.castAs,
      fixture.sample,
      fixture.row,
    ] as const,
)

describe('a legacy DynamoDB read reconstructs every plaintext axis', () => {
  let handedToFfi: Array<Record<string, unknown>>
  let decrypted: Array<Record<string, unknown>>
  let singleRow: Record<string, unknown>

  beforeAll(async () => {
    const bulk = ffiStub({ wire, tables: [matrix] })
    decrypted = unwrapResult(
      await bulk.dynamo.bulkDecryptModels(storedRows, matrix, {
        storedEqlVersion: 2,
      }),
    )
    handedToFfi = bulk.received

    const single = ffiStub({ wire, tables: [matrix] })
    singleRow = unwrapResult(
      await single.dynamo.decryptModel(storedRows[0], matrix, {
        storedEqlVersion: 2,
      }),
    )
  })

  /**
   * The matrix must actually have been driven. An empty plan — or one whose
   * cases stopped reaching this file — leaves every `it.each` below silently
   * ABSENT rather than red, which is the one failure mode a green run cannot
   * show. The axis list itself is pinned once, repo-wide, in
   * `__tests__/test-kit-v2-fixtures.test.ts`; asserted here is only that this
   * suite drives all of it, and that the axes needing runtime repair are among
   * them (`json` is absent by declaration — no v2 ste_vec fixture can be minted
   * — and its adapter half is pinned separately below).
   */
  it('drives every case the v2 fixture plan produces', () => {
    expect(plan.domains.length).toBeGreaterThan(0)
    expect(matrixCases.length).toBe(plan.cases.length)
    expect(handedToFfi).toHaveLength(plan.rowCount)

    const axes = new Set(plan.cases.map((fixture) => fixture.castAs))
    for (const axis of ['date', 'timestamp', 'bigint'] as const) {
      expect(axes.has(axis), `${axis} left this suite's matrix`).toBe(true)
    }
  })

  it.each(matrixCases)(
    '%s: rebuilds a v2 envelope and reconstructs the plaintext',
    (label, slug, castAs, sample, row) => {
      // THE guard for this file. Rebuilt as v2 — `k: 'ct'` and `v: 2` — around
      // the CURRENT v3 descriptor's identifier, carrying the stored ciphertext
      // untouched. Drop the version branch and this goes red per domain.
      expect(handedToFfi[row]?.[slug]).toEqual({
        i: { c: slug, t: matrix.tableName },
        v: 2,
        k: 'ct',
        c: ciphertext({ slug, row }),
      })

      expectReconstructed(decrypted[row]?.[slug], castAs, sample, label)
    },
  )

  /**
   * `decryptModel` and `bulkDecryptModels` are separate wrappers over the same
   * reconstructor, and only the bulk one is exercised above. A row's worth of
   * domains through the single path catches the wrapper being wired up without
   * its `map`.
   */
  it('reconstructs the same values on the single-model read', () => {
    const firstRow = plan.cases.filter((fixture) => fixture.row === 0)
    expect(firstRow.length).toBe(plan.domains.length)
    for (const fixture of firstRow) {
      expectReconstructed(
        singleRow[fixture.slug],
        fixture.castAs,
        fixture.sample,
        `${fixture.label} (single model)`,
      )
    }
  })

  it('hands the FFI a model with no storage attributes left on it', () => {
    const keys = Object.keys(handedToFfi[0] ?? {})
    expect(keys.filter((key) => key.endsWith('__source'))).toEqual([])
    // `__hmac` is a query term, not data: it must not reach the FFI as a field
    // to decrypt, and must not reach the caller as part of the model.
    expect(keys.filter((key) => key.endsWith('__hmac'))).toEqual([])
    expect([...hasSearchTerm.values()]).toContain(true)
  })

  it('passes undeclared attributes through both ways', () => {
    expect(handedToFfi[0]?.pk).toBe('item#0')
    expect(decrypted[0]?.pk).toBe('item#0')
    expect(decrypted[0]?.note).toBe('passthrough')
  })
})

// ---------------------------------------------------------------------------
// Nested (dotted-path) columns
// ---------------------------------------------------------------------------

/**
 * A nested date read from a stored v2 item is the sharpest case on this path:
 * `reconstructDatePaths` is path-aware (it walks segments and rebuilds nested
 * objects without mutating the input), and the path it walks comes from the v3
 * descriptor while the envelope around it is v2.
 */
describe('nested columns on a legacy read', () => {
  const people = encryptedTable('people', {
    'profile.birthday': types.Date('profile_birthday'),
    'profile.seenAt': types.Timestamp('profile_seen_at'),
    'profile.name': types.TextEq('profile_name'),
  })

  const stored = {
    pk: 'person#1',
    profile: {
      birthday__source: 'ct:birthday',
      seenAt__source: 'ct:seen-at',
      name__source: 'ct:name',
      name__hmac: 'hmac:name',
      nickname: 'ada',
    },
  }

  const nestedWire = {
    'ct:birthday': '1990-04-05T00:00:00.000Z',
    'ct:seen-at': '2026-07-01T12:34:56.000Z',
    'ct:name': 'Ada Lovelace',
  }

  it('rebuilds a v2 envelope at the declared dotted path', async () => {
    const { dynamo, received } = ffiStub({
      wire: nestedWire,
      tables: [people],
    })

    await dynamo.decryptModel(stored, people, { storedEqlVersion: 2 })

    // Matched by dotted path, identified by DB column name — the two differ
    // here (`profile.birthday` vs `profile_birthday`), which is exactly where a
    // read path that matched on one and identified with the other would break.
    expect(received[0]).toEqual({
      pk: 'person#1',
      profile: {
        birthday: {
          i: { c: 'profile_birthday', t: 'people' },
          v: 2,
          k: 'ct',
          c: 'ct:birthday',
        },
        seenAt: {
          i: { c: 'profile_seen_at', t: 'people' },
          v: 2,
          k: 'ct',
          c: 'ct:seen-at',
        },
        name: {
          i: { c: 'profile_name', t: 'people' },
          v: 2,
          k: 'ct',
          c: 'ct:name',
        },
        nickname: 'ada',
      },
    })
  })

  it('reconstructs a nested date and timestamp from a stored v2 item', async () => {
    const { dynamo } = ffiStub({ wire: nestedWire, tables: [people] })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(stored, people, { storedEqlVersion: 2 }),
    )
    const profile = (decrypted as { profile: Record<string, unknown> }).profile

    expect(profile.birthday).toBeInstanceOf(Date)
    expect(profile.birthday).toEqual(new Date('1990-04-05T00:00:00.000Z'))
    // `timestamp` keeps the time of day; a truncating regression would leave
    // midnight here and still be a `Date`.
    expect(profile.seenAt).toBeInstanceOf(Date)
    expect((profile.seenAt as Date).toISOString()).toBe(
      '2026-07-01T12:34:56.000Z',
    )
    expect(profile.name).toBe('Ada Lovelace')
    // Siblings survive; the query term does not.
    expect(profile.nickname).toBe('ada')
    expect(profile).not.toHaveProperty('name__hmac')
  })

  it('reconstructs nested dates on the bulk read too', async () => {
    const { dynamo } = ffiStub({ wire: nestedWire, tables: [people] })

    const rows = unwrapResult(
      await dynamo.bulkDecryptModels([stored, stored], people, {
        storedEqlVersion: 2,
      }),
    )

    expect(rows).toHaveLength(2)
    for (const row of rows) {
      const profile = (row as { profile: Record<string, unknown> }).profile
      expect(profile.birthday).toBeInstanceOf(Date)
      expect(profile.seenAt).toBeInstanceOf(Date)
    }
  })
})

/**
 * The gap this file found, now closed.
 *
 * A v2 GROUPED column registered its build key on the bare leaf, so a field
 * inside a group was stored as `<group>.<leaf>__source` while the schema knew it
 * only as `<leaf>`. `makeColumnMatcher`'s bare-leaf fallback (v2 reads only)
 * exists precisely so those attributes still rebuild — see the
 * `stored EQL v2 grouped fields` block in `helpers-v3.test.ts`.
 *
 * The envelope is rebuilt at the NESTED position (`details.birthday`), but the
 * clients key date reconstruction on the DECLARED path (`birthday`) — native via
 * `rowReconstructor`, WASM via `dateFields` — so neither found it and the value
 * came back as the FFI's string. The read path now reports the actual path it
 * wrote to and the adapter reconstructs there, so a grouped date carries forward
 * as a `Date` without the caller having to re-declare it as a dotted path.
 */
describe('a v2 grouped date column reconstructs at its nested path', () => {
  const orders = encryptedTable('orders', {
    birthday: types.Date('birthday'),
    label: types.Text('label'),
  })

  it('rebuilds the envelope under the group and reconstructs the date', async () => {
    const { dynamo, received } = ffiStub({
      wire: { 'ct:grouped': '1990-04-05T00:00:00.000Z' },
      tables: [orders],
    })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(
        { details: { birthday__source: 'ct:grouped' } },
        orders,
        { storedEqlVersion: 2 },
      ),
    )

    // The bare-leaf fallback did its job: the value decrypts.
    expect(received[0]).toEqual({
      details: {
        birthday: {
          i: { c: 'birthday', t: 'orders' },
          v: 2,
          k: 'ct',
          c: 'ct:grouped',
        },
      },
    })
    const details = (decrypted as { details: Record<string, unknown> }).details
    expect(details.birthday).toBeInstanceOf(Date)
    expect(details.birthday).toEqual(new Date('1990-04-05T00:00:00.000Z'))
  })

  it('reconstructs a grouped date on the bulk read too', async () => {
    const { dynamo } = ffiStub({
      wire: { 'ct:grouped': '1990-04-05T00:00:00.000Z' },
      tables: [orders],
    })

    const rows = unwrapResult(
      await dynamo.bulkDecryptModels(
        [
          { details: { birthday__source: 'ct:grouped' } },
          { details: { birthday__source: 'ct:grouped' } },
        ],
        orders,
        { storedEqlVersion: 2 },
      ),
    )

    for (const row of rows) {
      const details = (row as { details: Record<string, unknown> }).details
      expect(details.birthday).toBeInstanceOf(Date)
    }
  })

  /**
   * A date-shaped STRING at a grouped non-date column must stay a string. The
   * reconstruction is driven by the column's `cast_as`, not by whether the value
   * happens to parse as a date, and this is the case that tells the two apart.
   */
  it('leaves a grouped text column alone even when its value parses as a date', async () => {
    const { dynamo } = ffiStub({
      wire: { 'ct:label': '1990-04-05T00:00:00.000Z' },
      tables: [orders],
    })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(
        { details: { label__source: 'ct:label' } },
        orders,
        { storedEqlVersion: 2 },
      ),
    )

    const details = (decrypted as { details: Record<string, unknown> }).details
    expect(details.label).toBe('1990-04-05T00:00:00.000Z')
    expect(details.label).not.toBeInstanceOf(Date)
  })
})

// ---------------------------------------------------------------------------
// JSON (ste_vec) documents
// ---------------------------------------------------------------------------

/**
 * The `json` axis, as far as it can be taken.
 *
 * No v2 JSON fixture can be minted at all — cipherstash-client 0.42 refuses to
 * emit a ste_vec ciphertext in EQL v2 mode, which is why `V2_MINT_DEFERRED`
 * excludes the domain and `V2_UNREACHABLE_CAST_AS` declares the axis
 * unreachable. Legacy v2 documents already on disk remain decryptable, so the
 * ADAPTER half is still worth pinning: given such an item, the envelope it
 * rebuilds must be a well-formed SteVec one carrying the stored `k`, `h` and
 * `sv`, and the document must reach the caller untouched (no date-like cast, so
 * no reconstruction).
 */
describe('a stored v2 JSON document', () => {
  const docs = encryptedTable('docs', { meta: types.Json('meta') })
  const entries = [{ s: 'sel', c: 'ct', a: false, hm: 'h' }]
  const document = { user: 'ada@example.com', roles: ['admin', 'eng'] }

  it('rebuilds the SteVec envelope with v: 2 and returns the document', async () => {
    const { dynamo, received } = ffiStub({
      wire: { 'key-header': document },
      tables: [docs],
    })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(
        { pk: 'doc#1', meta__source: { h: 'key-header', sv: entries } },
        docs,
        { storedEqlVersion: 2 },
      ),
    )

    // `k: 'sv'` and the per-document KeyHeader `h` are mandatory — protect-ffi
    // 0.30 deserialization fails without either, and there is no root `c` to
    // fall back on.
    expect(received[0]).toEqual({
      pk: 'doc#1',
      meta: {
        i: { c: 'meta', t: 'docs' },
        v: 2,
        k: 'sv',
        h: 'key-header',
        sv: entries,
      },
    })
    expect(decrypted).toEqual({ pk: 'doc#1', meta: document })
  })
})

// ---------------------------------------------------------------------------
// bigint
// ---------------------------------------------------------------------------

/**
 * `PlaintextFromKind` promises `bigint`, and the table-aware overload returns
 * `V3DecryptedModel<Table, T>` — so the TYPE says `bigint` on a legacy read
 * exactly as it does on a v3 one. The matrix above asserts `typeof === 'bigint'`
 * for every bigint domain, which proves this path does not degrade a native
 * bigint.
 *
 * What it cannot prove is the other half: reconstruction is DATE-ONLY
 * (`rowReconstructor` filters on `DATE_LIKE_CASTS`; its docblock notes bigint
 * "needs none — protect-ffi returns a native JS bigint on decrypt"). If a v2
 * int8 payload ever decrypted to a string, nothing between the FFI and the
 * caller would convert it, and the type would be lying. Whether it does is a
 * protect-ffi question, answered by the live v2 matrix in
 * `integration/shared/v2-decrypt-compat.integration.test.ts`.
 *
 * This case pins the consequence so the division of labour is visible rather
 * than assumed: the adapter path adds no repair, so the type's promise rests
 * entirely on the FFI.
 */
describe('bigint is carried, never repaired', () => {
  const ledger = encryptedTable('ledger', {
    balance: types.BigintEq('balance'),
    at: types.Date('at'),
  })

  it('carries a native bigint through the legacy read unchanged', async () => {
    const { dynamo } = ffiStub({
      wire: { 'ct:balance': 9223372036854775807n },
      tables: [ledger],
    })

    const decrypted = unwrapResult(
      await dynamo.decryptModel({ balance__source: 'ct:balance' }, ledger, {
        storedEqlVersion: 2,
      }),
    )

    expect(typeof (decrypted as { balance: unknown }).balance).toBe('bigint')
    expect((decrypted as { balance: unknown }).balance).toBe(
      9223372036854775807n,
    )
  })

  it('does not coerce a bigint the FFI hands back as a string', async () => {
    const { dynamo } = ffiStub({
      wire: { 'ct:balance': '9223372036854775807', 'ct:at': '2026-07-01' },
      tables: [ledger],
    })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(
        { balance__source: 'ct:balance', at__source: 'ct:at' },
        ledger,
        { storedEqlVersion: 2 },
      ),
    )

    // The date-like column beside it IS repaired, from the same descriptor and
    // the same read — so this is a deliberate scope, not a broken reconstructor.
    expect((decrypted as { at: unknown }).at).toBeInstanceOf(Date)
    expect(typeof (decrypted as { balance: unknown }).balance).toBe('string')
  })
})

// ---------------------------------------------------------------------------
// The refusals a legacy read keeps
// ---------------------------------------------------------------------------

describe('legacy reads still refuse what they always refused', () => {
  const registered = encryptedTable('registered', {
    email: types.TextEq('email'),
  })
  const unregistered = encryptedTable('unregistered', {
    email: types.TextEq('email'),
  })
  const stored = { email__source: 'ct:email' }
  const wireMap = { 'ct:email': 'ada@example.com' }

  it('reads the registered table on the legacy path', async () => {
    const { dynamo } = ffiStub({ wire: wireMap, tables: [registered] })

    expect(
      unwrapResult(
        await dynamo.decryptModel(stored, registered, { storedEqlVersion: 2 }),
      ),
    ).toEqual({ email: 'ada@example.com' })
  })

  /**
   * The boundary `v2-decrypt-compat.integration.test.ts` pins live, reproduced
   * here without credentials. `assertClientTableVersionMatch` early-returns for
   * `storedEqlVersion: 2` — a v2 payload proves nothing about the client's v3
   * tables — but the adapter still forwards the table into the TABLE-AWARE
   * `decryptModel` overload (deliberately, to preserve Date reconstruction), and
   * that overload rejects a table outside the client's schema tuple. So a legacy
   * DynamoDB read does require the table to be declared in
   * `Encryption({ schemas })`, unlike the client's table-less reads.
   */
  it('fails with a clear error when the table was never registered', async () => {
    const { dynamo } = ffiStub({ wire: wireMap, tables: [registered] })

    const result = await dynamo.decryptModel(stored, unregistered, {
      storedEqlVersion: 2,
    })

    expect(result.failure?.message).toMatch(/was not initialized with/)
    // The failure arm carries no `data` at all — not an empty model that a
    // caller could mistake for a row with every encrypted field missing.
    expect('data' in result).toBe(false)

    const bulk = await dynamo.bulkDecryptModels([stored], unregistered, {
      storedEqlVersion: 2,
    })
    expect(bulk.failure?.message).toMatch(/was not initialized with/)
  })

  /**
   * The contrast that shows the early return is real: the SAME unregistered
   * table on a v3 read is rejected earlier and louder, by the adapter's own
   * guard, synchronously — before any client call.
   */
  it('rejects the same table earlier on a v3 read', () => {
    const { dynamo } = ffiStub({ wire: wireMap, tables: [registered] })

    expect(() => dynamo.decryptModel(stored, unregistered)).toThrow(
      /EQL version mismatch/,
    )
  })

  it('rejects an unsupported stored version before touching the client', () => {
    const { dynamo, received } = ffiStub({
      wire: wireMap,
      tables: [registered],
    })

    expect(() =>
      dynamo.decryptModel(stored, registered, {
        storedEqlVersion: 4,
      } as never),
    ).toThrow(/unsupported storedEqlVersion 4/)
    expect(() =>
      dynamo.bulkDecryptModels([stored], registered, {
        storedEqlVersion: 4,
      } as never),
    ).toThrow(/unsupported storedEqlVersion 4/)
    expect(received).toEqual([])
  })
})
