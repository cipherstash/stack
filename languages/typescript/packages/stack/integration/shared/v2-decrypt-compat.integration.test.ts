/**
 * Native v2 read compatibility after removal of the public v2 authoring path.
 *
 * Fixtures are minted directly with protect-ffi in EQL v2 mode. This is
 * deliberately integration-only: production callers cannot select v2 writes,
 * while the native v3 client must continue to decrypt data written before the
 * upgrade.
 *
 * Three blocks. The first two are about SURFACES (which read path), the third is
 * about TYPES (which plaintext axis), and the SECOND is the one that carries the
 * promise:
 *
 *  - `native v3 client reads stored EQL v2 payloads` — a v3 client reads v2 data
 *    for a table it still registers. The everyday case, but a weak detector: the
 *    reading client is configured for exactly the table the fixtures name, so it
 *    would keep passing even if decrypt started resolving payloads through the
 *    encrypt config.
 *  - `a client that never registered the v2 table still reads its payloads` —
 *    the same fixtures, read through a client configured ONLY for an unrelated
 *    table. This is what a real customer is left with: they migrated, their
 *    schema is whatever they author today, and their database still holds v2
 *    rows for columns their current schema may no longer mention at all.
 *  - `a v3 client reconstructs every plaintext axis…` — the same read, across
 *    the domain catalog rather than a single `TextEq` column. See that block's
 *    own header for why the type axis needs separate proof from the surface axis.
 *
 * The unrelated table is the entire point of the second block, and it is not
 * obvious on sight: it forces the reads to prove that decrypt is
 * PAYLOAD-SHAPE-DRIVEN and never consults the encrypt config. Nothing looks up
 * `i.t` / `i.c` — `isEncryptedPayload` selects fields structurally
 * (`src/encryption/helpers/index.ts`, `helpers/model-traversal.ts`) and
 * protect-ffi's `decrypt` accepts either wire generation regardless of the
 * client's own `eqlVersion`. Delete the unrelated table, or point these reads
 * back at `users`, and the block silently stops testing anything.
 *
 * The invariant is scoped to the client's TABLE-LESS reads. The DynamoDB
 * adapter always forwards a table, and the table-aware overload does consult
 * the schema tuple — so legacy DynamoDB reads require the table to be declared
 * in `Encryption({ schemas })`. The last case in the second block pins that
 * boundary so the difference is not mistaken for a regression later.
 *
 * Whatever next removes code here must keep that second block alive. It is the
 * successor to the `#1c` case that guarded this invariant while the
 * `config: { eqlVersion: 2 }` escape hatch still existed; the hatch is gone
 * (`Encryption()` now rejects the field outright), the invariant is not.
 */
import type { JsPlaintext } from '@cipherstash/protect-ffi'
import {
  encrypt as ffiEncrypt,
  encryptBulk as ffiEncryptBulk,
  newClient as newFfiClient,
} from '@cipherstash/protect-ffi'
import {
  unwrapResult,
  V3_MATRIX,
  v2FixtureColumns,
  v2FixturePlan,
  v2ModelRows,
  v2OpeIndexedDomains,
  v2UndeclaredCastAs,
} from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toEncryptedDynamoItem } from '@/dynamodb/helpers'
import { buildEncryptConfig, encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import type { CastAs } from '@/schema'
import type { Encrypted } from '@/types'

const users = encryptedTable('v2_read_compat_users', {
  email: types.TextEq('email'),
  altEmail: types.TextEq('alt_email'),
})

/**
 * A DIFFERENT table, sharing no name or column with `users`. `unrelatedClient`
 * below is built on this one alone, so its encrypt config has never heard of
 * `v2_read_compat_users` — which is what makes the reads in the second describe
 * block load-bearing rather than incidental.
 */
const unrelated = encryptedTable('v2_read_compat_unrelated_v3', {
  note: types.TextEq('note'),
})

const SECRET = 'ada@example.com'
let fixtureClient: Awaited<ReturnType<typeof newFfiClient>>
let client: Awaited<ReturnType<typeof makeClient>>
let unrelatedClient: Awaited<ReturnType<typeof makeUnrelatedClient>>

const makeClient = () => Encryption({ schemas: [users] })
// Typed through a thunk for the same reason as `makeClient`: a concrete schema
// tuple selects the typed overload, whose result is not the nominal client type.
const makeUnrelatedClient = () => Encryption({ schemas: [unrelated] })

beforeAll(async () => {
  fixtureClient = await newFfiClient({
    encryptConfig: buildEncryptConfig(users),
    eqlVersion: 2,
  })
  client = await makeClient()
  unrelatedClient = await makeUnrelatedClient()
})

async function v2Ciphertext(value: string): Promise<Encrypted> {
  return (await ffiEncrypt(fixtureClient, {
    plaintext: value,
    table: users.tableName,
    column: users.email.getName(),
  })) as Encrypted
}

describe('native v3 client reads stored EQL v2 payloads', () => {
  it('decrypts a scalar ciphertext', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    expect(encrypted).toMatchObject({ v: 2 })

    expect(unwrapResult(await client.decrypt(encrypted))).toBe(SECRET)
  }, 30000)

  it('decrypts a model without registering a legacy schema', async () => {
    const encrypted = await v2Ciphertext(SECRET)

    expect(
      unwrapResult(await client.decryptModel({ pk: 'a', email: encrypted })),
    ).toEqual({ pk: 'a', email: SECRET })
  }, 30000)

  /**
   * The state a real migration actually leaves behind: rows written before the
   * upgrade sit alongside rows written after, and a single model carries both.
   * Every other case here is all-v2, which is only ever true immediately before
   * the first v3 write.
   */
  it('decrypts a model mixing v2 and v3 fields', async () => {
    const legacy = await v2Ciphertext(SECRET)
    const current = unwrapResult(
      await client.encrypt('grace@example.com', {
        table: users,
        column: users.altEmail,
      }),
    )
    expect(legacy).toMatchObject({ v: 2 })
    expect(current).toMatchObject({ v: 3 })

    expect(
      unwrapResult(
        await client.decryptModel(
          { pk: 'a', email: legacy, altEmail: current },
          users,
        ),
      ),
    ).toEqual({ pk: 'a', email: SECRET, altEmail: 'grace@example.com' })
  }, 30000)

  it('bulk-decrypts v2 ciphertexts', async () => {
    // protect-ffi's `EncryptPayload` is `{ plaintext, column, table, lockContext? }`
    // — it carries no `id`, and correlates results positionally. The `id`s below
    // belong to `bulkDecrypt`, which is this package's own API and does take them.
    const encrypted = (await ffiEncryptBulk(fixtureClient, {
      plaintexts: [
        { plaintext: SECRET, table: users.tableName, column: 'email' },
        {
          plaintext: 'grace@example.com',
          table: users.tableName,
          column: 'email',
        },
      ],
    })) as Encrypted[]

    const decrypted = unwrapResult(
      await client.bulkDecrypt([
        { id: '1', data: encrypted[0] },
        { id: '2', data: encrypted[1] },
      ]),
    )
    expect(decrypted).toEqual([
      { id: '1', data: SECRET },
      { id: '2', data: 'grace@example.com' },
    ])
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
})

/**
 * The invariant customers actually depend on: decrypt is driven by the payload,
 * never by the encrypt config. Every read below goes through `unrelatedClient`,
 * which is configured for `v2_read_compat_unrelated_v3` and nothing else, while
 * the fixtures carry `i.t = 'v2_read_compat_users'`. A customer whose schema
 * dropped or renamed a column — or who never re-declared it after migrating to
 * v3 — must still be able to read the v2 rows already on disk.
 *
 * Keep this block reading through `unrelatedClient`. Swapping it for `client`
 * would leave every assertion green while testing nothing the block above does
 * not already cover.
 */
describe('a client that never registered the v2 table still reads its payloads', () => {
  // Precondition for everything below. If `unrelatedClient` ever ends up
  // registering `users` — a stray schema added here, a factory that merges
  // configs — the cases become indistinguishable from the first block and pass
  // vacuously. Assert the absence directly rather than trusting the setup.
  it('is configured for the unrelated table alone, or the cases below prove nothing', () => {
    const tables = unrelatedClient.getEncryptConfig()?.tables
    expect(Object.keys(tables ?? {})).toEqual([unrelated.tableName])
    expect(tables).not.toHaveProperty(users.tableName)
  })

  it('decrypts a scalar ciphertext for an unregistered table', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    // Guard against a false pass: this must be genuinely v2 wire, and it must
    // name the table the reading client does not have.
    expect(encrypted).toMatchObject({
      v: 2,
      i: { t: users.tableName, c: 'email' },
    })

    expect(unwrapResult(await unrelatedClient.decrypt(encrypted))).toBe(SECRET)
  }, 30000)

  it('decrypts a model whose encrypted field belongs to an unregistered table', async () => {
    const encrypted = await v2Ciphertext(SECRET)

    // No table argument: field selection is structural (`isEncryptedPayload`),
    // so there is nothing for the client to look the column up in.
    expect(
      unwrapResult(
        await unrelatedClient.decryptModel({ pk: 'a', email: encrypted }),
      ),
    ).toEqual({ pk: 'a', email: SECRET })
  }, 30000)

  it('bulk-decrypts ciphertexts for an unregistered table', async () => {
    // Minted one at a time rather than through `ffiEncryptBulk`: the bulk path
    // is on the READ side here, and the fixtures only need to be v2. (The
    // block above already covers the bulk mint.)
    const [first, second] = await Promise.all([
      v2Ciphertext(SECRET),
      v2Ciphertext('grace@example.com'),
    ])

    const decrypted = unwrapResult(
      await unrelatedClient.bulkDecrypt([
        { id: '1', data: first },
        { id: '2', data: second },
      ]),
    )
    expect(decrypted).toEqual([
      { id: '1', data: SECRET },
      { id: '2', data: 'grace@example.com' },
    ])
  }, 30000)

  /**
   * The DynamoDB adapter does NOT extend the guarantee above, and this case
   * pins that boundary rather than asserting it away.
   *
   * There are two independent registration checks on this path, and clearing
   * the first does not clear the second. `assertClientTableVersionMatch`
   * (`src/dynamodb/index.ts`) early-returns for `storedEqlVersion: 2`, because
   * a v2 payload says nothing about which v3 tables the client holds. But the
   * adapter then forwards the table into `client.decryptModel(item, table)` —
   * deliberately, to preserve Date reconstruction — and the TABLE-AWARE
   * overload rejects a table outside the schema tuple
   * (`src/encryption/client-v3.ts`). The native reads above survive because
   * they use the table-LESS overload, which has no such map to miss.
   *
   * The pre-#815 version of this case passed a v2 table descriptor, which side-
   * stepped the v3 guard entirely. That shape is now unreproducible: the v2
   * builders are gone, so the only descriptor that exists is a v3 one. Reading
   * legacy DynamoDB data therefore requires declaring the table in
   * `Encryption({ schemas })` — a real constraint, not a regression, and one
   * the caller must already satisfy to have a descriptor to pass.
   */
  it('refuses a stored v2 DynamoDB item whose table the client never registered', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    const stored = toEncryptedDynamoItem({ pk: 'a', email: encrypted }, [
      'email',
    ])
    const dynamo = encryptedDynamoDB({ encryptionClient: unrelatedClient })

    const result = await dynamo.decryptModel(stored, users, {
      storedEqlVersion: 2,
    })

    expect(result.failure?.message).toMatch(/was not initialized with/)
  }, 30000)
})

/**
 * The TYPE axis of the same obligation. Everything above reads v2 payloads from
 * a single `types.TextEq` column, so it proves the SURFACES (scalar / model /
 * bulk / mixed / DynamoDB / unregistered table) and nothing about what happens
 * to a `date`, a `bigint`, or a `boolean` on the way back.
 *
 * That gap is not cosmetic, because reconstruction is driven by the v3 table's
 * `cast_as` and applied REGARDLESS of the payload's wire version:
 *
 *  - `date` / `timestamp` — `DATE_LIKE_CASTS` (`src/eql/v3/columns.ts`) selects
 *    the date properties, `rowReconstructor` (`src/encryption/client-v3.ts`)
 *    rebuilds them via `reconstructDatePaths`. A v2 payload read through a v3
 *    descriptor gets that treatment; nothing here has ever checked the result.
 *  - `bigint` — the sharpest case. `PlaintextFromKind` promises `bigint` and the
 *    table-aware overload returns `V3DecryptedModel<Table, T>`, so the TYPE says
 *    `bigint` even on a legacy read. Native `bigint` on decrypt is a property of
 *    the v3 path; whether a v2 payload yields the same is exactly what was
 *    unverified. Asserted with an explicit `typeof`, not a loose equality — if
 *    v2 hands back a string, that is a product defect and this must say so.
 *
 * Structure mirrors `matrix-crypto.integration.test.ts`, which does the same for
 * v3 writes: driven from `V3_MATRIX` (compile-time exhaustive, so a new domain
 * cannot be forgotten), one mega table spanning every mintable domain, and the
 * whole matrix through ONE `encryptBulk` + ONE `bulkDecryptModels` rather than
 * ~100 sequential calls.
 *
 * Reads go through the MODEL path deliberately: that is where reconstruction
 * happens. The single-value `decrypt` of a date-like column returns the stored
 * string by design, and the last case pins that boundary rather than hiding it.
 *
 * Domain SELECTION lives in `@cipherstash/test-kit`'s `v2-fixtures`, not here:
 * the WASM and DynamoDB surfaces need the same set, and three files quietly
 * disagreeing about which domains they cover is the failure this whole file
 * exists to prevent. Exclusions are declared there with a written reason, and
 * the first three cases below are the accounting that keeps them honest.
 *
 * That selection deliberately ignores `DomainSpec.deferred`, which is about a
 * Postgres operator class being superuser-only. No table is created here and no
 * row is stored — this is pure crypto, exactly like `matrix-crypto`, which
 * likewise covers the block-ORE domains. Mixing the two exclusion axes would
 * drop domains for a reason that does not apply.
 */
const matrixPlan = v2FixturePlan()
const matrix = encryptedTable(
  'v2_read_compat_matrix',
  v2FixtureColumns(matrixPlan),
)

// Typed through a thunk for the same reason as `makeClient` above.
const makeMatrixClient = () => Encryption({ schemas: [matrix] })

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
      // `reconstructDatePaths` must have run off the v3 table's cast_as even
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

describe('a v3 client reconstructs every plaintext axis from stored EQL v2 payloads', () => {
  let matrixFixtureClient: Awaited<ReturnType<typeof newFfiClient>>
  let matrixClient: Awaited<ReturnType<typeof makeMatrixClient>>
  let encrypted: Array<Record<string, Encrypted>>
  let decrypted: Array<Record<string, unknown>>
  let singleRow: Record<string, unknown>

  beforeAll(async () => {
    matrixFixtureClient = await newFfiClient({
      encryptConfig: buildEncryptConfig(matrix),
      eqlVersion: 2,
    })
    matrixClient = await makeMatrixClient()

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
    decrypted = unwrapResult(
      await matrixClient.bulkDecryptModels(encrypted, matrix),
    )
    singleRow = unwrapResult(
      await matrixClient.decryptModel(encrypted[0], matrix),
    )
  }, 60000)

  it('accounts for every catalog domain as either minted or deferred', () => {
    const accounted = [
      ...matrixPlan.domains.map((domain) => domain.eqlType),
      ...matrixPlan.deferred.map((domain) => domain.eqlType),
    ].sort()
    // The partition is the coverage mechanism: a domain that is in neither set
    // has been dropped, and one in both would be counted twice.
    expect(accounted).toEqual(Object.keys(V3_MATRIX).sort())
    expect(matrixPlan.domains.length).toBeGreaterThan(0)
    for (const { eqlType, reason } of matrixPlan.deferred) {
      expect(reason, `${eqlType} is deferred with no reason`).not.toBe('')
    }
  })

  /**
   * The exclusions are a hand-written list so that a NEW domain defaults to
   * covered and fails loudly. This is what stops that list drifting away from
   * the rule it claims to encode: the deferred set must be exactly the
   * `ope`-indexed domains (no such v2 payload can exist — EQL v2 scalars carry
   * `hm`/`bf`/`ob`, never `op`) plus the one `ste_vec` domain the shipped client
   * refuses to write in v2 mode. Add an ope-indexed domain and this goes red
   * with a diff naming it, rather than silently skipping it.
   */
  it('defers exactly the domains its written reasons cover', () => {
    expect(matrixPlan.deferred.map((domain) => domain.eqlType).sort()).toEqual(
      [...v2OpeIndexedDomains(), 'public.eql_v3_json_search'].sort(),
    )
  })

  /**
   * Deferring a domain is normally free, because decrypt reconstructs from
   * `cast_as` and every deferred domain shares its `cast_as` with a covered one.
   * Deferring the LAST domain on an axis is not free, and would otherwise be
   * invisible — the suite would still show ~100 green cases.
   */
  it('loses no plaintext axis to a deferral without declaring it', () => {
    expect(v2UndeclaredCastAs(matrixPlan)).toEqual([])
    // Pinned, not derived: this is the list of axes the v2 READ path is actually
    // proven on. `json` is absent and declared unreachable — no v2 ste_vec
    // fixture can be minted with cipherstash-client 0.42.
    expect(
      [...new Set(matrixPlan.cases.map((fixture) => fixture.castAs))].sort(),
    ).toEqual(['bigint', 'boolean', 'date', 'number', 'string', 'timestamp'])
  })

  it.each(matrixCases)(
    '%s decrypts from a stored EQL v2 payload through the model path',
    (label, slug, castAs, sample, row) => {
      const payload = encrypted[row][slug]

      // THE guard for this file. Without it the whole matrix would pass just as
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
    },
  )

  /**
   * `decryptModel` and `bulkDecryptModels` are separate wrappers over the same
   * reconstructor, and only the bulk one is exercised above. A row's worth of
   * domains through the single path is enough to catch the wrapper being wired
   * up without its `map`.
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
   * property of the MODEL path, which has a table to read `cast_as` from. A
   * single-value `decrypt` has no table, so it returns the stored string — the
   * same contract v3 has, and the reason the matrix above reads through models.
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
})
