/**
 * Property-based coverage (fast-check) for the DynamoDB attribute mapping.
 *
 * The example-based suites (`helpers.test.ts`, `helpers-v3.test.ts`) pin the
 * mapping pointwise. Four data-integrity bugs still slipped through all of
 * them, because every one needed a *shape the examples never wrote down*: a
 * plaintext key that happens to collide with an EQL envelope key, an attribute
 * that happens to end in a storage suffix, a `Date` in a cloned model, a column
 * whose JS property name differs from its DB name. These are the cross-cutting
 * invariants that make those shapes unrepresentable rather than merely untested:
 *
 *   1. ROUND TRIP: for any column set and any ciphertext,
 *      `toItemWithEqlPayloads(toEncryptedDynamoItem(x))` preserves every
 *      ciphertext and rebuilds the envelope the FFI will accept — scalar
 *      (untagged) and ste_vec (`k: 'sv'`) alike.
 *   2. PASSTHROUGH: an item with NO encrypted payloads is returned unchanged by
 *      BOTH directions, at any nesting depth, for any attribute name —
 *      including names that collide with envelope keys (`c`, `hm`, `k`, `sv`,
 *      `v`, `i`) and with the storage suffixes (`legit__hmac`, `img__source`).
 *   3. NO ATTRIBUTE LOSS: neither direction ever reduces the top-level key
 *      count of an all-plaintext item.
 *   4. deepClone is identity-preserving, `Date`-preserving, and shares no
 *      object reference with its source.
 *   5. VERSION FOLLOWS THE TABLE: a v3 table always yields `v: 3` and never
 *      `k: 'ct'`; a v2 table always yields `v: 2` with `k: 'ct'`.
 *   6. NO ENVELOPE METADATA LEAK: a split scalar writes only `<attr>__source`
 *      (plus `<attr>__hmac` when `hm` is present) and never leaks `k`/`v`/`i`
 *      into a stored attribute value.
 *   7. PROPERTY vs DB NAME: the stored attribute is keyed by the JS PROPERTY
 *      name while the rebuilt identifier `i.c` is the DB name.
 *
 * Every property here is pure — no client, no credentials, no network. The one
 * live property (a ZeroKMS `decryptModel(encryptModel(x))` round trip) lives in
 * `encrypted-dynamodb-v3.test.ts` with the rest of the live suite.
 */
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import {
  ciphertextAttrSuffix,
  deepClone,
  isV3Table,
  searchTermAttrSuffix,
  toEncryptedDynamoItem,
  toItemWithEqlPayloads,
} from '@/dynamodb/helpers'
import { encryptedTable, types } from '@/eql/v3'
import {
  encryptedColumn,
  encryptedField,
  encryptedTable as encryptedTableV2,
} from '@/schema'

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * `EncryptedTable.build()` THROWS on duplicate DB names and `encryptedTable()`
 * throws on a column name that shadows a table member, so generated schemas are
 * kept inside a charset that can produce neither: lowercase, max 8 chars (too
 * short to contain a `__source`/`__hmac` suffix), minus the one reserved word
 * the charset can reach.
 */
const RESERVED_COLUMN_NAMES = new Set(['build'])

/** The plaintext attribute the payload properties carry alongside the columns. */
const PLAINTEXT_KEY = 'zz_plain'

const safeName = fc
  .stringMatching(/^[a-z][a-z0-9_]{0,7}$/)
  .filter((n) => !RESERVED_COLUMN_NAMES.has(n) && n !== PLAINTEXT_KEY)

/** Ciphertexts are never empty in practice, and the write path tests truthiness. */
const ciphertext = fc.string({ minLength: 1 })

/** ste_vec entries, as the FFI emits them for a JSON document. */
const steVecEntries = fc.array(
  fc.record({ s: fc.string(), c: fc.string({ minLength: 1 }) }),
  { minLength: 1, maxLength: 3 },
)

/**
 * Attribute names chosen to be maximally hostile to the mapping's heuristics:
 * six that collide with EQL envelope keys, two with the storage suffixes.
 */
const hostileKey = fc.oneof(
  fc.constantFrom('c', 'hm', 'k', 'sv', 'v', 'i', 'legit__hmac', 'img__source'),
  safeName,
)

/** An all-plaintext attribute tree: no value anywhere is an EQL payload. */
const plaintextValue = fc.letrec<{ node: unknown; leaf: unknown }>((tie) => ({
  leaf: fc.oneof(
    fc.string(),
    fc.integer(),
    fc.boolean(),
    fc.constant(null),
    fc.double({ noNaN: true }),
  ),
  node: fc.oneof(
    { maxDepth: 3, depthSize: 'small' },
    tie('leaf'),
    fc.array(tie('node'), { maxLength: 3 }),
    fc.dictionary(hostileKey, tie('node'), { maxKeys: 4 }),
  ),
})).node

const plaintextItem = fc.dictionary(hostileKey, plaintextValue, { maxKeys: 5 })

/**
 * Would the mapping's payload detector see an envelope anywhere in this tree?
 *
 * The detector is a heuristic — `v` + `i` + (`c` | `sv`) — so an all-plaintext
 * object that happens to carry exactly those three keys is genuinely
 * indistinguishable from a payload and is *supposed* to be rewritten. The
 * passthrough properties are about everything else, so those cases are
 * discarded rather than asserted (documenting the heuristic's exact blind spot).
 */
function looksLikeEnvelope(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(looksLikeEnvelope)
  const hasEnvelopeKeys =
    'v' in value && 'i' in value && ('c' in value || 'sv' in value)
  return hasEnvelopeKeys || Object.values(value).some(looksLikeEnvelope)
}

// ---------------------------------------------------------------------------
// 1. ROUND TRIP
// ---------------------------------------------------------------------------

/** A generated v3 schema plus one payload per column. */
const roundTripCase = fc
  .uniqueArray(safeName, { minLength: 1, maxLength: 5 })
  .chain((names) =>
    fc.record({
      names: fc.constant(names),
      kinds: fc.tuple(
        ...names.map(() => fc.constantFrom('scalar' as const, 'json' as const)),
      ),
      cts: fc.tuple(...names.map(() => ciphertext)),
      svs: fc.tuple(...names.map(() => steVecEntries)),
      // The per-document SteVec KeyHeader (`h`). Opaque to the mapping, but
      // protect-ffi 0.30 decrypt requires it, so it must survive the round trip.
      hs: fc.tuple(...names.map(() => fc.string({ minLength: 1 }))),
      hms: fc.tuple(
        ...names.map(() =>
          fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
        ),
      ),
      plain: fc.string(),
    }),
  )

describe('property: write → read round trip', () => {
  it('preserves every ciphertext and rebuilds the envelope, for any column set', () => {
    fc.assert(
      fc.property(
        roundTripCase,
        ({ names, kinds, cts, svs, hs, hms, plain }) => {
          const table = encryptedTable(
            'users',
            Object.fromEntries(
              names.map((n, idx) => [
                n,
                kinds[idx] === 'json' ? types.Json(n) : types.TextEq(n),
              ]),
            ),
          )
          const encryptedAttrs = Object.keys(table.buildColumnKeyMap())

          const item: Record<string, unknown> = { [PLAINTEXT_KEY]: plain }
          const expectedStored: Record<string, unknown> = {
            [PLAINTEXT_KEY]: plain,
          }
          const expectedRebuilt: Record<string, unknown> = {
            [PLAINTEXT_KEY]: plain,
          }

          names.forEach((name, idx) => {
            const i = { t: 'users', c: name }
            if (kinds[idx] === 'json') {
              // A SteVec document stores its `sv` entries plus the KeyHeader `h`
              // (0.30 decrypt requires `h`); `v`/`i`/`k` are rebuilt on read.
              item[name] = { v: 3, k: 'sv', i, h: hs[idx], sv: svs[idx] }
              expectedStored[`${name}${ciphertextAttrSuffix}`] = {
                h: hs[idx],
                sv: svs[idx],
              }
              expectedRebuilt[name] = {
                i: { c: name, t: 'users' },
                v: 3,
                k: 'sv',
                h: hs[idx],
                sv: svs[idx],
              }
              return
            }
            item[name] = {
              v: 3,
              i,
              c: cts[idx],
              ...(hms[idx] === undefined ? {} : { hm: hms[idx] }),
            }
            expectedStored[`${name}${ciphertextAttrSuffix}`] = cts[idx]
            if (hms[idx] !== undefined) {
              expectedStored[`${name}${searchTermAttrSuffix}`] = hms[idx]
            }
            // The search term is a write-side index, not part of the envelope:
            // the read path drops it rather than round-tripping it.
            expectedRebuilt[name] = {
              i: { c: name, t: 'users' },
              v: 3,
              c: cts[idx],
            }
          })

          const stored = toEncryptedDynamoItem(item, encryptedAttrs)
          expect(stored).toEqual(expectedStored)
          expect(toItemWithEqlPayloads(stored, table)).toEqual(expectedRebuilt)
        },
      ),
    )
  })
})

// ---------------------------------------------------------------------------
// 2. PASSTHROUGH — pins two of the four review bugs
// ---------------------------------------------------------------------------

describe('property: plaintext passthrough (both directions)', () => {
  const users = encryptedTable('users', {
    email: types.TextEq('email'),
    note: types.Text('note'),
    meta: types.Json('meta'),
  })
  const encryptedAttrs = Object.keys(users.buildColumnKeyMap())

  it('the write path returns an item with no payloads unchanged, at any depth', () => {
    // BUG PINNED: a nested plaintext object with a `c` key was mistaken for a
    // ciphertext, rewritten to `<attr>__source`, and every sibling key
    // DISCARDED — silent data loss on a PutCommand.
    fc.assert(
      fc.property(plaintextItem, (item) => {
        fc.pre(!looksLikeEnvelope(item))
        expect(toEncryptedDynamoItem(item, encryptedAttrs)).toEqual(item)
      }),
      { numRuns: 1000 },
    )
  })

  it('the read path returns an item with no envelopes unchanged, at any depth', () => {
    // BUG PINNED: ANY attribute ending in `__hmac` was dropped on read, so a
    // customer's own `signature__hmac` vanished; and any nested `*__source` was
    // handed to the FFI as if it were a ciphertext.
    fc.assert(
      fc.property(plaintextItem, (item) => {
        expect(toItemWithEqlPayloads(item, users)).toEqual(item)
      }),
      { numRuns: 1000 },
    )
  })

  // ---------------------------------------------------------------------------
  // 3. NO ATTRIBUTE LOSS
  // ---------------------------------------------------------------------------

  it('neither direction reduces the top-level key count of an all-plaintext item', () => {
    fc.assert(
      fc.property(plaintextItem, (item) => {
        fc.pre(!looksLikeEnvelope(item))
        const keys = Object.keys(item)
        const written = toEncryptedDynamoItem(item, encryptedAttrs)
        const read = toItemWithEqlPayloads(item, users)

        expect(Object.keys(written).length).toBeGreaterThanOrEqual(keys.length)
        expect(Object.keys(read).length).toBeGreaterThanOrEqual(keys.length)
        for (const key of keys) {
          expect(written).toHaveProperty([key])
          expect(read).toHaveProperty([key])
        }
      }),
      { numRuns: 1000 },
    )
  })
})

// ---------------------------------------------------------------------------
// 4. deepClone
// ---------------------------------------------------------------------------

/** Every object/array reachable from `value`, cycle-safe. */
function objectRefs(value: unknown, seen = new Set<object>()): Set<object> {
  if (value === null || typeof value !== 'object') return seen
  if (seen.has(value)) return seen
  seen.add(value)
  for (const child of Object.values(value)) objectRefs(child, seen)
  return seen
}

describe('property: deepClone', () => {
  // BUG PINNED: the previous hand-rolled `Object.entries` reduce flattened every
  // non-plain object to `{}`, silently destroying `Date` values and making the
  // whole `types.Timestamp*` / `types.Date*` domain family unusable here.
  it('is identity-preserving over arbitrary JSON documents', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(deepClone(value)).toEqual(value)
      }),
    )
  })

  it('preserves a Date as a real Date with the same time', () => {
    fc.assert(
      fc.property(fc.date({ noInvalidDate: true }), (at) => {
        const cloned = deepClone({ at, nested: { at } })
        expect(cloned.at).toBeInstanceOf(Date)
        expect(cloned.at.getTime()).toBe(at.getTime())
        expect(cloned.nested.at).toBeInstanceOf(Date)
        expect(cloned.nested.at.getTime()).toBe(at.getTime())
      }),
    )
  })

  it('shares no object reference with its source', () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string(), fc.jsonValue(), { minKeys: 1 }),
        (value) => {
          const cloned = deepClone(value)
          const sourceRefs = objectRefs(value)
          for (const ref of objectRefs(cloned)) {
            expect(sourceRefs.has(ref)).toBe(false)
          }
        },
      ),
    )
  })
})

// ---------------------------------------------------------------------------
// 5. VERSION FOLLOWS THE TABLE
// ---------------------------------------------------------------------------

describe('property: the rebuilt wire version follows the table', () => {
  it('a v3 table always yields v: 3 and never a k: "ct" tag', () => {
    fc.assert(
      fc.property(safeName, ciphertext, (name, ct) => {
        const table = encryptedTable('t', { [name]: types.TextEq(name) })
        expect(isV3Table(table)).toBe(true)

        const rebuilt = toItemWithEqlPayloads(
          { [`${name}${ciphertextAttrSuffix}`]: ct },
          table,
        )[name] as Record<string, unknown>

        expect(rebuilt.v).toBe(3)
        expect(rebuilt).not.toHaveProperty('k')
        expect(rebuilt.c).toBe(ct)
      }),
    )
  })

  it('a v3 JSON column keeps v: 3, the mandatory k: "sv", and the KeyHeader', () => {
    fc.assert(
      fc.property(
        safeName,
        steVecEntries,
        fc.string({ minLength: 1 }),
        (name, entries, h) => {
          const table = encryptedTable('t', { [name]: types.Json(name) })

          const rebuilt = toItemWithEqlPayloads(
            { [`${name}${ciphertextAttrSuffix}`]: { h, sv: entries } },
            table,
          )[name] as Record<string, unknown>

          expect(rebuilt.v).toBe(3)
          expect(rebuilt.k).toBe('sv')
          // The per-document KeyHeader survives — 0.30 decrypt requires it.
          expect(rebuilt.h).toBe(h)
          expect(rebuilt.sv).toEqual(entries)
        },
      ),
    )
  })

  it('a v2 table always yields v: 2 with k: "ct"', () => {
    fc.assert(
      fc.property(safeName, ciphertext, (name, ct) => {
        const table = encryptedTableV2('t', {
          [name]: encryptedColumn(name).equality(),
        })
        expect(isV3Table(table)).toBe(false)

        const rebuilt = toItemWithEqlPayloads(
          { [`${name}${ciphertextAttrSuffix}`]: ct },
          table,
        )[name] as Record<string, unknown>

        expect(rebuilt.v).toBe(2)
        expect(rebuilt.k).toBe('ct')
        expect(rebuilt.c).toBe(ct)
      }),
    )
  })

  it('a v2 table with a grouped field still yields v: 2 with k: "ct"', () => {
    fc.assert(
      fc.property(safeName, safeName, ciphertext, (group, leaf, ct) => {
        const table = encryptedTableV2('t', {
          [group]: { [leaf]: encryptedField(`${group}.${leaf}`) },
        })
        expect(isV3Table(table)).toBe(false)

        const rebuilt = toItemWithEqlPayloads(
          { [group]: { [`${leaf}${ciphertextAttrSuffix}`]: ct } },
          table,
        )[group] as Record<string, Record<string, unknown>>

        expect(rebuilt[leaf]?.v).toBe(2)
        expect(rebuilt[leaf]?.k).toBe('ct')
      }),
    )
  })
})

// ---------------------------------------------------------------------------
// 6. NO ENVELOPE METADATA LEAK
// ---------------------------------------------------------------------------

/** Does any value in this tree carry an envelope metadata key? */
function hasEnvelopeMetadata(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(hasEnvelopeMetadata)
  if ('k' in value || 'v' in value || 'i' in value) return true
  return Object.values(value).some(hasEnvelopeMetadata)
}

describe('property: no envelope metadata reaches storage', () => {
  it('a split scalar writes only __source (and __hmac when hm is present)', () => {
    fc.assert(
      fc.property(
        safeName,
        ciphertext,
        fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
        // Terms with no DynamoDB query surface: they must be dropped, not stored.
        fc.record({
          op: fc.option(fc.string(), { nil: undefined }),
          ob: fc.option(fc.array(fc.string()), { nil: undefined }),
          bf: fc.option(fc.array(fc.integer()), { nil: undefined }),
        }),
        (name, ct, hm, noise) => {
          const table = encryptedTable('t', { [name]: types.TextEq(name) })
          const stored = toEncryptedDynamoItem(
            {
              [name]: {
                v: 3,
                i: { t: 't', c: name },
                c: ct,
                ...(hm === undefined ? {} : { hm }),
                ...noise,
              },
            },
            Object.keys(table.buildColumnKeyMap()),
          )

          const expectedKeys = [`${name}${ciphertextAttrSuffix}`]
          if (hm !== undefined) {
            expectedKeys.push(`${name}${searchTermAttrSuffix}`)
          }
          expect(Object.keys(stored).sort()).toEqual(expectedKeys.sort())
          expect(stored[`${name}${ciphertextAttrSuffix}`]).toBe(ct)
          for (const value of Object.values(stored)) {
            expect(hasEnvelopeMetadata(value)).toBe(false)
          }
        },
      ),
    )
  })

  it('a ste_vec document is stored as its entries plus KeyHeader, no envelope metadata', () => {
    fc.assert(
      fc.property(
        safeName,
        steVecEntries,
        fc.string({ minLength: 1 }),
        (name, entries, h) => {
          const table = encryptedTable('t', { [name]: types.Json(name) })
          const stored = toEncryptedDynamoItem(
            {
              [name]: { v: 3, k: 'sv', i: { t: 't', c: name }, h, sv: entries },
            },
            Object.keys(table.buildColumnKeyMap()),
          )

          expect(Object.keys(stored)).toEqual([
            `${name}${ciphertextAttrSuffix}`,
          ])
          expect(stored[`${name}${ciphertextAttrSuffix}`]).toEqual({
            h,
            sv: entries,
          })
          // `v`/`i`/`k` are reconstructed on read, never stored.
          expect(hasEnvelopeMetadata(stored)).toBe(false)
        },
      ),
    )
  })
})

// ---------------------------------------------------------------------------
// 7. PROPERTY vs DB NAME — the most severe bug found in review
// ---------------------------------------------------------------------------

describe('property: attributes are keyed by property name, identified by DB name', () => {
  // BUG PINNED: the two names were conflated. A column declared
  // `emailAddress: types.TextEq('email_address')` was matched against the DB
  // name, so the attribute was never split on write, its `__hmac` was never
  // emitted (killing every key-condition query on it), and on read the mapping
  // recursed into the payload instead of rebuilding it.
  const distinctNames = fc
    .tuple(safeName, safeName)
    .filter(([property, dbName]) => property !== dbName)

  it('splits under the property name and rebuilds i.c as the DB name', () => {
    fc.assert(
      fc.property(
        distinctNames,
        ciphertext,
        fc.string({ minLength: 1 }),
        ([property, dbName], ct, hm) => {
          const table = encryptedTable('t', {
            [property]: types.TextEq(dbName),
          })

          const stored = toEncryptedDynamoItem(
            { [property]: { v: 3, i: { t: 't', c: dbName }, c: ct, hm } },
            Object.keys(table.buildColumnKeyMap()),
          )

          // Keyed by the PROPERTY name — the DB name never appears in storage.
          expect(stored).toEqual({
            [`${property}${ciphertextAttrSuffix}`]: ct,
            [`${property}${searchTermAttrSuffix}`]: hm,
          })

          // Identified by the DB name — this is what the FFI looks up.
          expect(toItemWithEqlPayloads(stored, table)).toEqual({
            [property]: { i: { c: dbName, t: 't' }, v: 3, c: ct },
          })
        },
      ),
    )
  })
})
