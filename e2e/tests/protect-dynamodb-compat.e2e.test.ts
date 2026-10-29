/**
 * Cross-version proof: DynamoDB items written by the REAL Protect.js stack a
 * customer runs today read back, and stay queryable, under Stack 1.x.
 *
 * Writer: `@cipherstash/protect@10.2.1` + `@cipherstash/protect-dynamodb@6.0.1`
 * (→ `@cipherstash/protect-ffi@0.18.1` → cipherstash-client 0.28), installed
 * from npm as pinned devDependencies of this package. Reader: the in-tree
 * `@cipherstash/stack` (→ the in-tree protect-ffi → cipherstash-client 0.42).
 *
 * Every other v2 test in the repo mints its "v2" fixtures with TODAY's
 * protect-ffi in v2 mode, so compatibility with ciphertext written by the old
 * native client rested on the record format being unchanged — argued from
 * source, pinned by nothing. This file pins it.
 *
 * Items are minted at test time, never committed: ciphertext and HMACs are bound
 * to the workspace keyset, so a committed fixture would decrypt in exactly one
 * workspace (the trap #1200 hit with pinned SteVec selectors). No DynamoDB is
 * involved either — both adapters' `encryptModel` / `decryptModel` are pure
 * transforms between a model and the item that would be `PutItem`'d.
 *
 * Needs the four `CS_*` credential variables. A `stash auth login` profile is
 * not enough: Protect 10.2.1 is configured from explicit credentials.
 * The `e2e-tests` job in `tests.yml` runs this file in its own step with
 * `CS_E2E_REQUIRE_AUTH=1`, which makes it throw rather than skip when they are
 * missing, so the `skipIf` below cannot hide a regression in CI.
 */
import { fileURLToPath } from 'node:url'
import { csColumn, csTable, protect } from '@cipherstash/protect'
import { protectDynamoDB } from '@cipherstash/protect-dynamodb'
import { encryptedDynamoDB } from '@cipherstash/stack/dynamodb'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import { config } from 'dotenv'
import { beforeAll, beforeEach, describe, expect, it } from 'vitest'

// A local `.env` in `e2e/` or at the repo root, as AGENTS.md describes. CI
// injects the variables directly; an existing value always wins.
config({
  path: ['../.env', '../../.env'].map((p) =>
    fileURLToPath(new URL(p, import.meta.url)),
  ),
  quiet: true,
})

const authConfigured = Boolean(
  process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)

/**
 * Build Protect's native client (cipherstash-client 0.28) for the same
 * workspace Stack uses.
 *
 * Unlike today's clients, 0.28 does not derive its service hosts from the
 * workspace CRN: with no override it defaults to the legacy
 * `ap-southeast-2.aws.auth.viturhosted.net`, so a workspace in another region
 * gets a 401 from CTS. So point `CS_CTS_HOST` / `CS_ZEROKMS_HOST` at the CRN's
 * region while the client is built, using the URLs current clients derive by
 * service discovery (cts-common's `CtsServiceDiscovery` and
 * `ZeroKmsServiceDiscovery`), then restore them: the hosts are read at
 * construction, and Stack's client must keep deriving its own. Credentials
 * are passed explicitly, as a Protect app configured from these variables
 * would.
 */
async function legacyProtect(
  schemas: Parameters<typeof protect>[0]['schemas'],
) {
  const crn = process.env.CS_WORKSPACE_CRN as string
  const region = crn.split(':')[1]
  const saved = {
    CS_CTS_HOST: process.env.CS_CTS_HOST,
    CS_ZEROKMS_HOST: process.env.CS_ZEROKMS_HOST,
  }
  process.env.CS_CTS_HOST = `https://${region}.cts.cipherstashmanaged.net`
  process.env.CS_ZEROKMS_HOST = `https://${region}.viturhosted.net`
  try {
    return await protect({
      schemas,
      workspaceCrn: crn,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
    })
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

/** Unwrap a `{ data } | { failure }` result, failing the test on `failure`. */
function ok<T>(
  result: { data: T; failure?: undefined } | { failure: unknown },
  label: string,
): T {
  if ('failure' in result && result.failure !== undefined) {
    const failure = result.failure as { message?: unknown }
    // An Error's message is not enumerable, so JSON.stringify alone drops it.
    throw new Error(
      `${label} failed: ${String(failure?.message ?? '')} ${JSON.stringify(failure)}`,
    )
  }
  return (result as { data: T }).data
}

// ---------------------------------------------------------------------------
// The schemas: the customer's v2 table, and its v3 mapping.
//
// Property keys and DB column names are identical on both sides, as the
// migration guidance requires: Stack finds `<key>__source` by property key.
// ---------------------------------------------------------------------------

const legacyUsers = csTable('users', {
  email: csColumn('email').equality(),
  emailLower: csColumn('emailLower').equality([{ kind: 'downcase' }]),
  age: csColumn('age').dataType('number').equality(),
  balance: csColumn('balance').dataType('bigint').equality(),
  birthday: csColumn('birthday').dataType('date').equality(),
  active: csColumn('active').dataType('boolean').equality(),
  notes: csColumn('notes'),
})

/** The domain mapping the migration doc recommends, one v3 domain per column. */
const users = encryptedTable('users', {
  email: types.TextEq('email'),
  emailLower: types.TextEq('emailLower'),
  age: types.IntegerEq('age'),
  balance: types.BigintEq('balance'),
  active: types.Boolean('active'),
  notes: types.Text('notes'),
})

/**
 * The same columns under DIFFERENT v3 domains, to pin which choices keep the
 * stored `__hmac` and which lose it. Only used for `encryptQuery`.
 */
const alternates = encryptedTable('users_alt', {
  age: types.DoubleEq('age'),
})

/** A v3 table may not name one DB column twice, so the *Ord domain lives apart. */
const ordered = encryptedTable('users_ord', {
  age: types.IntegerOrd('age'),
})

/**
 * Renamed table AND renamed DB column names, same property keys. The doc claims
 * neither name is needed to decrypt: the column name is bound into the record
 * as AEAD associated data, but it travels inside the ciphertext.
 */
const renamed = encryptedTable('people_v3', {
  email: types.TextEq('email_address'),
  notes: types.Text('free_text'),
})

/** Protect's `dataType('json')` column, and the v3 domain it backfills to. */
const legacyDocs = csTable('docs', {
  profile: csColumn('profile').dataType('json'),
})
const docs = encryptedTable('docs', { profile: types.Json('profile') })

const model = {
  pk: 'user#1',
  email: 'ada@example.com',
  emailLower: 'Ada@Example.com',
  age: 36,
  // protect 10.2.1 takes a bigint column's value only as a JS number (a JS
  // bigint or a string is rejected), so stay inside Number.MAX_SAFE_INTEGER.
  balance: 1_234_567_890_123,
  active: true,
  notes: 'first programmer',
}

// Where CI promises credentials, a skip would read as a pass: their absence is
// a wiring bug (turbo's strict env mode filters them out, for one).
if (process.env.CS_E2E_REQUIRE_AUTH === '1' && !authConfigured) {
  throw new Error(
    'protect-dynamodb-compat: CS_E2E_REQUIRE_AUTH is set but CS_WORKSPACE_CRN, CS_CLIENT_ID, CS_CLIENT_KEY and CS_CLIENT_ACCESS_KEY did not all reach the test process',
  )
}

describe.skipIf(!authConfigured)(
  'protect-dynamodb 6.0.1 items under Stack 1.x',
  () => {
    let legacyClient: Awaited<ReturnType<typeof protect>>
    let legacy: ReturnType<typeof protectDynamoDB>
    let stack: ReturnType<typeof encryptedDynamoDB>
    let client: Awaited<ReturnType<typeof Encryption>>
    /** One item exactly as protect-dynamodb 6.0.1 would `PutItem` it. */
    let item: Record<string, unknown>

    /** The `hm` term Stack 1.x mints for a value, or undefined if none. */
    const hmOf = async (
      value: unknown,
      table: typeof users | typeof alternates | typeof ordered | typeof renamed,
      column: unknown,
    ): Promise<string | undefined> => {
      const term = ok(
        await client.encryptQuery(
          value as never,
          {
            table,
            column,
          } as never,
        ),
        'encryptQuery',
      )
      return (term as { hm?: string } | null)?.hm
    }

    beforeAll(async () => {
      legacyClient = await legacyProtect([legacyUsers, legacyDocs])
      legacy = protectDynamoDB({ protectClient: legacyClient })

      client = await Encryption({
        schemas: [users, alternates, ordered, renamed, docs],
      })
      stack = encryptedDynamoDB({ encryptionClient: client })

      item = ok(
        await legacy.encryptModel(model, legacyUsers),
        'protect-dynamodb encryptModel',
      )
    }, 60_000)

    it('stores only __source and __hmac — no EQL version on disk', () => {
      expect(Object.keys(item).sort()).toEqual(
        [
          'pk',
          'email__source',
          'email__hmac',
          'emailLower__source',
          'emailLower__hmac',
          'age__source',
          'age__hmac',
          'balance__source',
          'balance__hmac',
          'active__source',
          'active__hmac',
          'notes__source',
        ].sort(),
      )
      for (const [key, value] of Object.entries(item)) {
        if (key === 'pk') continue
        expect(typeof value, key).toBe('string')
      }
    })

    // -------------------------------------------------------------------------
    // Q1 — does v2 ciphertext decrypt under v3 tooling?
    // -------------------------------------------------------------------------

    describe('Q1: decrypt', () => {
      it('reads the item with storedEqlVersion: 2', async () => {
        const decrypted = ok(
          await stack.decryptModel(item, users, { storedEqlVersion: 2 }),
          'stack decryptModel (v2)',
        )
        expect(decrypted).toMatchObject({
          pk: 'user#1',
          email: model.email,
          emailLower: model.emailLower,
          age: model.age,
          active: true,
          notes: model.notes,
        })
        expect(decrypted.balance).toBe(BigInt(model.balance))
      })

      it('reads the same item with no storedEqlVersion at all (scalars carry no version)', async () => {
        const asV2 = ok(
          await stack.decryptModel(item, users, { storedEqlVersion: 2 }),
          'v2 read',
        )
        const asV3 = ok(await stack.decryptModel(item, users), 'v3 read')
        expect(asV3).toEqual(asV2)
        // No leftover `*__source` key: nothing was silently passed through.
        expect(Object.keys(asV3).filter((k) => k.endsWith('__source'))).toEqual(
          [],
        )
      })

      it('agrees with what protect-dynamodb itself decrypts', async () => {
        const fromLegacy = ok(
          await legacy.decryptModel(item, legacyUsers),
          'protect-dynamodb decryptModel',
        )
        const fromStack = ok(
          await stack.decryptModel(item, users, { storedEqlVersion: 2 }),
          'stack decryptModel',
        )
        for (const key of [
          'email',
          'emailLower',
          'age',
          'active',
          'notes',
        ] as const) {
          expect(fromStack[key], key).toEqual(fromLegacy[key])
        }
      })

      it('changes the JS type of a bigint column, but not its value', async () => {
        const fromLegacy = ok(
          await legacy.decryptModel(item, legacyUsers),
          'protect-dynamodb decryptModel',
        )
        const fromStack = ok(
          await stack.decryptModel(item, users, { storedEqlVersion: 2 }),
          'stack decryptModel',
        )

        // Stack 1.x: a native bigint. Protect: a number. Same value.
        expect(typeof fromStack.balance).toBe('bigint')
        expect(typeof fromLegacy.balance).not.toBe('bigint')
        expect(BigInt(fromLegacy.balance as number | string)).toBe(
          fromStack.balance,
        )
      })

      it('passes raw ciphertext through, with no failure, when a property key was renamed', async () => {
        const drifted = encryptedTable('users', {
          emailAddress: types.TextEq('email'),
        })
        const driftClient = await Encryption({ schemas: [drifted] })
        const decrypted = ok(
          await encryptedDynamoDB({
            encryptionClient: driftClient,
          }).decryptModel(
            { pk: item.pk, email__source: item.email__source },
            drifted,
            { storedEqlVersion: 2 },
          ),
          'drifted decryptModel',
        )
        expect(decrypted).not.toHaveProperty('emailAddress')
        expect(decrypted.email__source).toBe(item.email__source)
      })

      it('reads on the bulk path too', async () => {
        const [decrypted] = ok(
          await stack.bulkDecryptModels([item], users, { storedEqlVersion: 2 }),
          'stack bulkDecryptModels',
        )
        expect(decrypted).toMatchObject({ email: model.email, age: model.age })
      })

      it('fails, never returns wrong plaintext, when the ciphertext is tampered with', async () => {
        const source = item.email__source as string
        // Flip one character well inside the Base85 body.
        const at = Math.floor(source.length / 2)
        const flipped = source[at] === 'A' ? 'B' : 'A'
        const tampered = {
          ...item,
          email__source: source.slice(0, at) + flipped + source.slice(at + 1),
        }
        const result = await stack.decryptModel(tampered, users, {
          storedEqlVersion: 2,
        })
        expect(result.failure).toBeDefined()
      })
    })

    // -------------------------------------------------------------------------
    // Q2 — are the HMACs the same?
    // -------------------------------------------------------------------------

    describe('Q2: __hmac', () => {
      it.each([
        ['email', 'TextEq', model.email, users.email],
        ['age', 'IntegerEq', model.age, users.age],
        ['balance', 'BigintEq', BigInt(model.balance), users.balance],
      ] as const)(
        '%s: Stack %s encryptQuery reproduces the stored __hmac',
        async (attr, _domain, value, column) => {
          const stored = item[`${attr}__hmac`]
          expect(stored).toMatch(/^[0-9a-f]{64}$/)
          expect(await hmOf(value, users, column)).toBe(stored)
        },
      )

      it('matches protect-dynamodb createSearchTerms for the same value', async () => {
        const [legacyTerm] = ok(
          await legacy.createSearchTerms([
            {
              value: model.email,
              column: legacyUsers.email,
              table: legacyUsers,
            },
          ]),
          'createSearchTerms',
        )
        expect(legacyTerm).toBe(item.email__hmac)
        expect(await hmOf(model.email, users, users.email)).toBe(legacyTerm)
      })

      it('every numeric *Eq domain gives the same HMAC (all cast to f64)', async () => {
        expect(await hmOf(model.age, alternates, alternates.age)).toBe(
          item.age__hmac,
        )
      })

      it('a numeric *Ord domain emits no HMAC at all', async () => {
        expect(await hmOf(model.age, ordered, ordered.age)).toBe(undefined)
      })

      it('protect 10.2.1 could not encrypt a date column at all, so no legacy date HMAC exists', async () => {
        for (const value of [
          '1990-04-05',
          '1990-04-05T00:00:00Z',
          new Date('1990-04-05'),
          Date.UTC(1990, 3, 5),
        ]) {
          const result = await legacyClient.encrypt(value as never, {
            table: legacyUsers,
            column: legacyUsers.birthday,
          })
          expect(
            (result as { failure?: { message?: string } }).failure?.message,
            String(value),
          ).toMatch(/Unsupported conversion from "(String|Number)" to Date/)
        }
      })

      it('a v3 Boolean writes no __hmac, though protect-dynamodb wrote one', async () => {
        expect(item.active__hmac).toMatch(/^[0-9a-f]{64}$/)
        const written = ok(
          await stack.encryptModel({ pk: 'user#4', active: true }, users),
          'stack encryptModel (boolean)',
        )
        expect(written.active__source).toBeDefined()
        expect(written).not.toHaveProperty('active__hmac')
      })

      it('a v2 downcase filter is reproduced only by lowercasing first', async () => {
        const stored = item.emailLower__hmac
        expect(await hmOf(model.emailLower, users, users.emailLower)).not.toBe(
          stored,
        )
        expect(
          await hmOf(model.emailLower.toLowerCase(), users, users.emailLower),
        ).toBe(stored)
      })
    })

    describe('downcase on the write path', () => {
      it('a Stack write keeps mixed-case plaintext only by giving up the legacy HMAC', async () => {
        const stored = item.emailLower__hmac
        const mixed = ok(
          await stack.encryptModel(
            { pk: 'user#5', emailLower: model.emailLower },
            users,
          ),
          'stack encryptModel (mixed case)',
        )
        expect(mixed.emailLower__hmac).not.toBe(stored)

        const lowered = ok(
          await stack.encryptModel(
            { pk: 'user#5', emailLower: model.emailLower.toLowerCase() },
            users,
          ),
          'stack encryptModel (lowercased)',
        )
        expect(lowered.emailLower__hmac).toBe(stored)
        // ...and the original case is gone from the stored plaintext.
        const read = ok(
          await stack.decryptModel(lowered, users),
          'stack decryptModel (lowercased)',
        )
        expect(read.emailLower).toBe(model.emailLower.toLowerCase())
      })
    })

    // -------------------------------------------------------------------------
    // Q3 — is table / column bound into the encryption?
    // -------------------------------------------------------------------------

    describe('Q3: binding', () => {
      it('decrypts under a renamed table and renamed DB column names', async () => {
        const subset = {
          pk: item.pk,
          email__source: item.email__source,
          email__hmac: item.email__hmac,
          notes__source: item.notes__source,
        }
        const decrypted = ok(
          await stack.decryptModel(subset, renamed, { storedEqlVersion: 2 }),
          'renamed decryptModel',
        )
        expect(decrypted).toMatchObject({
          email: model.email,
          notes: model.notes,
        })
      })

      it('the HMAC is bound to neither table nor column', async () => {
        expect(await hmOf(model.email, renamed, renamed.email)).toBe(
          item.email__hmac,
        )
      })
    })

    // -------------------------------------------------------------------------
    // Rollback — Stack 1.x writes, the old reader reads.
    // -------------------------------------------------------------------------

    describe('rollback', () => {
      it('an item written by Stack 1.x reads back through protect-dynamodb 6.0.1', async () => {
        const written = ok(
          await stack.encryptModel(
            {
              pk: 'user#2',
              email: 'grace@example.com',
              age: 85,
              notes: 'compiler',
            },
            users,
          ),
          'stack encryptModel',
        )
        const read = ok(
          await legacy.decryptModel(written, legacyUsers),
          'protect-dynamodb decryptModel',
        )
        expect(read).toMatchObject({
          pk: 'user#2',
          email: 'grace@example.com',
          age: 85,
          notes: 'compiler',
        })
      })

      it('Stack 1.x writes the same __hmac protect-dynamodb wrote', async () => {
        const written = ok(
          await stack.encryptModel({ pk: 'user#3', email: model.email }, users),
          'stack encryptModel',
        )
        expect(written.email__hmac).toBe(item.email__hmac)
      })
    })

    // -------------------------------------------------------------------------
    // Acceptance: the migration a customer runs, end to end. The "table" is a
    // Map: both adapters' items are flat string attributes, so PutItem /
    // UpdateItem persistence is a copy, and an equality query on an encrypted
    // attribute is a match on its `__hmac`.
    // -------------------------------------------------------------------------

    describe('acceptance: legacy write → mixed update → backfill → query → rollback', () => {
      // Fresh per test: a row left by one test would add a match to another's
      // exact-count query, so results would depend on test order.
      const table = new Map<string, Record<string, unknown>>()
      beforeEach(() => table.clear())
      const queryBy = (attr: string, hm: string | undefined) =>
        [...table.values()].filter((row) => row[`${attr}__hmac`] === hm)

      it('runs the migration and keeps every generation readable and queryable', async () => {
        // 1. Legacy write, as protect-dynamodb 6.0.1 left it.
        table.set('user#1', { ...item })

        // 2. Mixed-generation item: Stack 1.x updates two attributes in place
        //    (UpdateItem SET), the rest stay as protect-dynamodb wrote them.
        const update = ok(
          await stack.encryptModel(
            { pk: 'user#1', email: 'ada.lovelace@example.com', age: 37 },
            users,
          ),
          'stack encryptModel (partial update)',
        )
        table.set('user#1', { ...table.get('user#1'), ...update })

        // One read call, no per-attribute version routing: scalars carry no
        // version, so the same call reads both generations.
        const mixed = ok(
          await stack.decryptModel(
            table.get('user#1') as Record<string, unknown>,
            users,
          ),
          'stack decryptModel (mixed)',
        )
        expect(mixed).toMatchObject({
          email: 'ada.lovelace@example.com',
          age: 37,
          emailLower: model.emailLower,
          active: true,
          notes: model.notes,
          balance: BigInt(model.balance),
        })

        // Queries hit both generations' HMACs.
        expect(
          queryBy(
            'email',
            await hmOf('ada.lovelace@example.com', users, users.email),
          ),
        ).toHaveLength(1)
        expect(
          queryBy(
            'emailLower',
            await hmOf(model.emailLower.toLowerCase(), users, users.emailLower),
          ),
        ).toHaveLength(1)

        // 3. Backfill: read, normalise what v3 no longer filters, re-encrypt
        //    with Stack 1.x, persist (PutItem replaces the whole item).
        const before = table.get('user#1') as Record<string, unknown>
        const rewritten = ok(
          await stack.encryptModel(
            { ...mixed, emailLower: String(mixed.emailLower).toLowerCase() },
            users,
          ),
          'stack encryptModel (backfill)',
        ) as Record<string, unknown>
        table.set('user#1', rewritten)

        // 4. Verify the persisted item: values back, and every query a caller
        //    could run before the backfill still finds it.
        const after = ok(
          await stack.decryptModel(rewritten, users),
          'stack decryptModel (backfilled)',
        )
        expect(after).toMatchObject({
          email: 'ada.lovelace@example.com',
          age: 37,
          emailLower: model.emailLower.toLowerCase(),
          active: true,
          notes: model.notes,
          balance: BigInt(model.balance),
        })
        for (const attr of ['email', 'emailLower', 'age', 'balance']) {
          expect(rewritten[`${attr}__hmac`], attr).toBe(before[`${attr}__hmac`])
        }
        // The one query the backfill cannot keep: a v3 Boolean has no HMAC.
        expect(rewritten).not.toHaveProperty('active__hmac')
        expect(queryBy('active', before.active__hmac as string)).toHaveLength(0)

        // 5. Rollback: the old reader still reads the backfilled item.
        const rolledBack = ok(
          await legacy.decryptModel(rewritten, legacyUsers),
          'protect-dynamodb decryptModel (backfilled)',
        )
        expect(rolledBack).toMatchObject({
          email: 'ada.lovelace@example.com',
          age: 37,
          emailLower: model.emailLower.toLowerCase(),
          active: true,
          notes: model.notes,
        })
        expect(Number(rolledBack.balance)).toBe(model.balance)
      })

      it('a Boolean partial update must REMOVE the stale legacy __hmac', async () => {
        const legacyTrue = item.active__hmac as string
        expect(legacyTrue).toMatch(/^[0-9a-f]{64}$/)

        const update = ok(
          await stack.encryptModel({ pk: 'user#6', active: false }, users),
          'stack encryptModel (boolean update)',
        ) as Record<string, unknown>
        expect(update).not.toHaveProperty('active__hmac')

        // SET only: the new ciphertext says false, the old HMAC still says
        // true, so an equality query for `true` finds an item that is false.
        table.set('user#6', { ...item, pk: 'user#6', ...update })
        const setOnly = ok(
          await stack.decryptModel(
            table.get('user#6') as Record<string, unknown>,
            users,
          ),
          'stack decryptModel (SET only)',
        )
        expect(setOnly.active).toBe(false)
        expect(queryBy('active', legacyTrue).map((row) => row.pk)).toContain(
          'user#6',
        )

        // SET + REMOVE active__hmac: the stale match is gone.
        const { active__hmac: _stale, ...removed } = table.get(
          'user#6',
        ) as Record<string, unknown>
        table.set('user#6', removed)
        expect(
          queryBy('active', legacyTrue).map((row) => row.pk),
        ).not.toContain('user#6')
      })
    })

    // -------------------------------------------------------------------------
    // The legacy JSON gap.
    // -------------------------------------------------------------------------

    describe('legacy dataType("json")', () => {
      const doc = { roles: ['admin', 'eng'], tz: 'Australia/Sydney' }
      let docItem: Record<string, unknown>
      /** The v2 scalar envelope Protect's `profile__source` came from. */
      let legacyEnvelope: {
        v: 2
        k: 'ct'
        i: { t: string; c: string }
        c: string
      }

      beforeAll(async () => {
        docItem = ok(
          await legacy.encryptModel({ pk: 'doc#1', profile: doc }, legacyDocs),
          'protect-dynamodb encryptModel (json)',
        )
        legacyEnvelope = {
          v: 2,
          k: 'ct',
          i: { t: 'docs', c: 'profile' },
          c: docItem.profile__source as string,
        }
      })

      it('was stored as a scalar ciphertext string, not a SteVec document', () => {
        expect(typeof docItem.profile__source).toBe('string')
      })

      it('fails to read through encryptedDynamoDB with types.Json (known gap)', async () => {
        const result = await stack.decryptModel(docItem, docs, {
          storedEqlVersion: 2,
        })
        expect(result.failure).toBeDefined()
      })

      it('reads through client.decrypt() on a rebuilt v2 scalar envelope', async () => {
        const decrypted = ok(
          await client.decrypt(legacyEnvelope),
          'client.decrypt (legacy json)',
        )
        expect(decrypted).toEqual(doc)
      })

      it('backfills to a types.Json item that Stack 1.x reads', async () => {
        const decrypted = ok(
          await client.decrypt(legacyEnvelope),
          'client.decrypt (legacy json)',
        )
        const rewritten = ok(
          await stack.encryptModel(
            { pk: 'doc#1', profile: decrypted as typeof doc },
            docs,
          ),
          'stack encryptModel (json backfill)',
        )
        const read = ok(
          await stack.decryptModel(rewritten, docs),
          'stack decryptModel (json backfill)',
        )
        expect(read.profile).toEqual(doc)
      })
    })
  },
)
