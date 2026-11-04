/**
 * Cross-version proof: DynamoDB items written by the REAL Protect.js stack a
 * customer runs today read back, and stay queryable, under Stack 1.x.
 *
 * Writer: `@cipherstash/protect@10.2.1` + `@cipherstash/protect-dynamodb@6.0.1`
 * (→ `@cipherstash/protect-ffi@0.18.1` → cipherstash-client 0.28), installed
 * from npm as pinned devDependencies of this package. Reader: the in-tree
 * `@cipherstash/stack` (→ the in-tree protect-ffi → cipherstash-client 0.42).
 *
 * A final, DEPRECATED block also pins `@cipherstash/stack@0.19.0` (aliased as
 * `@cipherstash/stack-0.19`) to show that the old Protect → 0.19 → 1.x route
 * still lands in the same place. That hop is no longer required.
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
 * Without them the file fails rather than skips: it proves a migration claim
 * made to customers, so a run that proved nothing must not read as a pass.
 * That is why the default `vitest.config.ts` leaves it out (turbo's strict env
 * mode hides the credentials from `test:e2e`) and it runs from its own config
 * as the `test:protect-compat` task, a step of its own (with
 * `--env-mode=loose`) in the `e2e-tests` job in `tests.yml`.
 *
 * `docs/migration/protect-dynamodb-to-stack.md` cites these tests by name, and
 * `protect-upgrade-guide.e2e.test.ts` fails when a cited name stops existing:
 * renaming or removing a test means updating the guide's claim with it.
 */
import { csColumn, csTable, type protect } from '@cipherstash/protect'
import { protectDynamoDB } from '@cipherstash/protect-dynamodb'
import { encryptedDynamoDB } from '@cipherstash/stack/dynamodb'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import { Encryption as Encryption019 } from '@cipherstash/stack-0.19'
import { encryptedDynamoDB as encryptedDynamoDB019 } from '@cipherstash/stack-0.19/dynamodb'
import {
  encryptedColumn as encryptedColumn019,
  encryptedTable as encryptedTable019,
} from '@cipherstash/stack-0.19/schema'
import { beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { authConfigured, legacyProtect, ok } from './helpers/legacy-protect'

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

// A skip would read as a pass, so missing credentials fail the file.
if (!authConfigured) {
  throw new Error(
    'protect-dynamodb-compat: CS_WORKSPACE_CRN, CS_CLIENT_ID, CS_CLIENT_KEY and CS_CLIENT_ACCESS_KEY must all be set (in the environment, e2e/.env or the repo-root .env)',
  )
}

describe('protect-dynamodb 6.0.1 items under Stack 1.x', () => {
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
      // Control: the untampered item decrypts, so a failure below comes
      // from the tampering and not from the service.
      ok(
        await stack.decryptModel(item, users, { storedEqlVersion: 2 }),
        'control decryptModel',
      )
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

    // Only the `encryptModel` check is Stack behaviour. The steps after it
    // show the DynamoDB consequence on the in-memory table: SET alone keeps
    // the stale legacy __hmac, and SET + REMOVE drops it.
    it('a Stack Boolean update writes no __hmac, so a partial update must REMOVE the legacy one', async () => {
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
      expect(queryBy('active', legacyTrue).map((row) => row.pk)).not.toContain(
        'user#6',
      )
    })
  })

  // -------------------------------------------------------------------------
  // No re-encryption: the upgrade is a code change only. A corpus written by
  // protect-dynamodb 6.0.1 is frozen, the app moves to Stack 1.x, and every
  // read and equality query keeps working against the stored bytes. The
  // backfill in the acceptance test above is optional; this block runs the
  // same app WITHOUT it. The proof that no rewrite is needed is that the reads
  // and queries pass against bytes nothing has rewritten; the last test only
  // confirms that Stack's reads left those bytes as they were.
  // -------------------------------------------------------------------------

  describe('no re-encryption: a code-only upgrade over untouched legacy items', () => {
    type Row = {
      pk: string
      email: string
      emailLower: string
      age: number
      balance: number
      active: boolean
      notes: string
    }
    // Shared values (age 36, a lowercase-equal emailLower) so a query has to
    // return exactly the right SET of rows, not just a single hit. The
    // balances cover zero, a negative and Number.MAX_SAFE_INTEGER, the largest
    // value protect 10.2.1 could store exactly (see `model.balance`).
    const corpus: Row[] = [
      {
        pk: 'user#10',
        email: 'grace@example.com',
        emailLower: 'Grace@Example.com',
        age: 36,
        balance: 0,
        active: true,
        notes: 'compilers',
      },
      {
        pk: 'user#11',
        email: 'alan@example.com',
        emailLower: 'ALAN@example.com',
        age: 41,
        balance: Number.MAX_SAFE_INTEGER,
        active: false,
        notes: 'computability',
      },
      {
        pk: 'user#12',
        email: 'edsger@example.com',
        emailLower: 'grace@example.com',
        age: 36,
        balance: -42,
        active: true,
        notes: 'structured programming',
      },
    ]
    /** What Stack 1.x returns for a row: identical, bigint as a JS bigint. */
    const expected = (row: Row) => ({ ...row, balance: BigInt(row.balance) })

    /** The table as protect-dynamodb left it. Items are frozen. */
    const table = new Map<string, Readonly<Record<string, unknown>>>()
    let snapshot: string
    const stored = () => [...table.values()]
    const queryBy = (
      rows: Readonly<Record<string, unknown>>[],
      attr: string,
      hm: string | undefined,
    ) =>
      rows
        .filter((row) => hm !== undefined && row[`${attr}__hmac`] === hm)
        .map((row) => row.pk as string)
        .sort()

    beforeAll(async () => {
      // Written before the upgrade, through both protect-dynamodb write paths.
      const [first, ...rest] = corpus
      const written = [
        ok(
          await legacy.encryptModel(first, legacyUsers),
          'protect-dynamodb encryptModel',
        ),
        ...ok(
          await legacy.bulkEncryptModels(rest, legacyUsers),
          'protect-dynamodb bulkEncryptModels',
        ),
      ] as Record<string, unknown>[]
      for (const row of written) table.set(row.pk as string, Object.freeze(row))
      // Frozen: every attribute is a top-level string, so a shallow freeze
      // covers the whole item. An in-place write by Stack throws if the
      // writing code is strict and is silently dropped if not, so the
      // snapshot is what catches either case in the last test.
      snapshot = JSON.stringify([...table.entries()])
    }, 60_000)

    // Nothing below touches `legacy` or `legacyClient`: from here on the app
    // runs on Stack 1.x alone, with the default read options.

    it('every legacy item decrypts, one at a time, with no read option', async () => {
      for (const row of corpus) {
        const decrypted = ok(
          await stack.decryptModel(
            table.get(row.pk) as Record<string, unknown>,
            users,
          ),
          `stack decryptModel ${row.pk}`,
        )
        expect(decrypted, row.pk).toEqual(expected(row))
      }
    })

    it('every legacy item decrypts in one bulk call', async () => {
      const decrypted = ok(
        await stack.bulkDecryptModels(
          stored() as Record<string, unknown>[],
          users,
        ),
        'stack bulkDecryptModels',
      )
      expect(decrypted).toEqual(corpus.map(expected))
    })

    it('every equality query finds exactly the legacy rows it should', async () => {
      const queries = [
        ['email', users.email, (r: Row) => r.email],
        // v3 has no downcase filter: the app lowercases the query value.
        [
          'emailLower',
          users.emailLower,
          (r: Row) => r.emailLower.toLowerCase(),
        ],
        ['age', users.age, (r: Row) => r.age],
        ['balance', users.balance, (r: Row) => BigInt(r.balance)],
      ] as const
      for (const [attr, column, project] of queries) {
        for (const row of corpus) {
          const value = project(row)
          const want = corpus
            .filter((r) => project(r) === value)
            .map((r) => r.pk)
            .sort()
          expect(
            queryBy(stored(), attr, await hmOf(value, users, column)),
            `${attr} = ${row.pk}'s value`,
          ).toEqual(want)
        }
      }
    })

    it('new Stack writes sit beside legacy items: one query and one bulk read cover both', async () => {
      const fresh = {
        pk: 'user#13',
        email: 'barbara@example.com',
        emailLower: 'barbara@example.com',
        age: 36,
        balance: 7n,
        active: false,
        notes: 'abstract data types',
      }
      const written = ok(
        await stack.encryptModel(fresh, users),
        'stack encryptModel (new item)',
      ) as Record<string, unknown>
      const mixed = [...stored(), written]

      expect(queryBy(mixed, 'age', await hmOf(36, users, users.age))).toEqual([
        'user#10',
        'user#12',
        'user#13',
      ])

      const decrypted = ok(
        await stack.bulkDecryptModels(mixed, users),
        'stack bulkDecryptModels (mixed generations)',
      )
      expect(decrypted).toEqual([...corpus.map(expected), fresh])
    })

    // Not a re-encryption requirement: re-encrypting would not bring it back,
    // because a v3 Boolean writes no __hmac either (see Q2). An app that
    // filters on a boolean needs a plaintext attribute or a GSI for it.
    it('the one query a Stack 1.x app cannot mint is a boolean equality, with or without a rewrite', async () => {
      for (const row of stored()) {
        expect(row.active__hmac, row.pk as string).toMatch(/^[0-9a-f]{64}$/)
      }
      // Control: the same client mints a term for a queryable column, so the
      // refusal below is about the Boolean domain, not the service.
      expect(await hmOf(model.email, users, users.email)).toBe(item.email__hmac)
      // A Boolean is storage-only: it carries no index, so the query is
      // refused before anything reaches ZeroKMS.
      const result = await client.encryptQuery(
        true as never,
        { table: users, column: users.active } as never,
      )
      expect(
        (result as { failure?: { message?: string } }).failure?.message,
      ).toMatch(/no indexes configured/)
    })

    // Runs last. Nothing in this block writes to `table`, so this cannot show
    // a write path leaves legacy items alone. It shows the reads and queries
    // above did not change the items they ran against.
    it("Stack's reads and queries left every stored item byte-identical", () => {
      expect(JSON.stringify([...table.entries()])).toBe(snapshot)
      expect(table.size).toBe(corpus.length)
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
      // Control: the same ciphertext decrypts through client.decrypt(), so
      // the failure below comes from the reader and not from the service.
      ok(await client.decrypt(legacyEnvelope), 'control client.decrypt')
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

  // -------------------------------------------------------------------------
  // DEPRECATED — NO LONGER REQUIRED: the Stack 0.19 bridge.
  //
  // Earlier migration guidance routed Protect apps through
  // `@cipherstash/stack@0.19.0` (the last release that writes EQL v2) before
  // Stack 1.x. Everything above proves the direct path — Protect 10.2.1 →
  // Stack 1.x — on its own, so that intermediate step is unnecessary. Do not
  // recommend it.
  //
  // This block exists only so the answer for anyone who already took the hop
  // is pinned rather than argued: a 0.19 deployment reads Protect's items,
  // writes items Stack 1.x reads, and writes the SAME `__hmac` values Protect
  // did, so the hop adds nothing and loses nothing. Delete the block, and the
  // `@cipherstash/stack-0.19` devDependency, when no customer is on 0.19.
  // -------------------------------------------------------------------------

  describe('DEPRECATED (no longer required): Protect 10.2.1 → Stack 0.19 → Stack 1.x', () => {
    /** The customer's v2 table, as a Stack 0.19 app declares it. */
    const bridgeUsers = encryptedTable019('users', {
      email: encryptedColumn019('email').equality(),
      emailLower: encryptedColumn019('emailLower').equality([
        { kind: 'downcase' },
      ]),
      age: encryptedColumn019('age').dataType('number').equality(),
      balance: encryptedColumn019('balance').dataType('bigint').equality(),
      active: encryptedColumn019('active').dataType('boolean').equality(),
      notes: encryptedColumn019('notes'),
    })
    /** Protect's item as Stack 0.19 reads it. */
    let read: Record<string, unknown>
    /** That read, re-written by Stack 0.19. */
    let bridged: Record<string, unknown>

    beforeAll(async () => {
      const bridgeClient = await Encryption019({ schemas: [bridgeUsers] })
      const bridge = encryptedDynamoDB019({ encryptionClient: bridgeClient })
      read = ok(
        await bridge.decryptModel(item, bridgeUsers),
        'stack 0.19 decryptModel (protect item)',
      )
      bridged = ok(
        await bridge.encryptModel(read, bridgeUsers),
        'stack 0.19 encryptModel',
      )
    }, 60_000)

    it('Stack 0.19 reads the Protect 10.2.1 item', () => {
      expect(read).toMatchObject({
        pk: 'user#1',
        email: model.email,
        emailLower: model.emailLower,
        age: model.age,
        active: true,
        notes: model.notes,
      })
      expect(BigInt(read.balance as number | bigint)).toBe(
        BigInt(model.balance),
      )
    })

    it('Stack 0.19 re-writes the same attributes and the same __hmac values Protect wrote', () => {
      expect(Object.keys(bridged).sort()).toEqual(Object.keys(item).sort())
      for (const key of Object.keys(item).filter((k) => k.endsWith('__hmac'))) {
        expect(bridged[key], key).toBe(item[key])
      }
    })

    it('Stack 1.x reads the 0.19-written item exactly as it reads the Protect item directly', async () => {
      const viaBridge = ok(
        await stack.decryptModel(bridged, users, { storedEqlVersion: 2 }),
        'stack decryptModel (0.19 item)',
      )
      const direct = ok(
        await stack.decryptModel(item, users, { storedEqlVersion: 2 }),
        'stack decryptModel (protect item)',
      )
      expect(viaBridge).toEqual(direct)
    })

    it('Stack 1.x queries find the 0.19-written item', async () => {
      expect(await hmOf(model.email, users, users.email)).toBe(
        bridged.email__hmac,
      )
      expect(await hmOf(model.age, users, users.age)).toBe(bridged.age__hmac)
      expect(await hmOf(BigInt(model.balance), users, users.balance)).toBe(
        bridged.balance__hmac,
      )
    })
  })
})
