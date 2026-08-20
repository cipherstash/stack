import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeEncryptedSupabase } from '../src/create'
import type { SupabaseClientLike } from '../src/types'

/**
 * Declared-schemas mode (#708).
 *
 * `encryptedSupabase` used to require a Postgres connection unconditionally,
 * because it derived every column's encryption config from the database's
 * domain types. That made the wrapper unconstructible anywhere a TCP socket to
 * Postgres is unavailable, and cost a second, more privileged credential even
 * on Node.
 *
 * The rule now: **declare your schemas and it runs anywhere; omit them and we
 * discover them for you, which needs a connection and is therefore Node-only.**
 * These tests pin the half that is new — construction with no database at all —
 * and, just as importantly, the things declared mode must give up *loudly*
 * rather than silently.
 */

const { introspectMock, encryptionMock } = vi.hoisted(() => ({
  introspectMock: vi.fn(),
  encryptionMock: vi.fn(),
}))

vi.mock('../src/introspect', async (importActual) => ({
  ...(await importActual<typeof import('../src/introspect')>()),
  introspect: (url: string) => introspectMock(url),
}))

vi.mock('@cipherstash/stack/encryption', async (importActual) => ({
  ...(await importActual<typeof import('@cipherstash/stack/encryption')>()),
  Encryption: (config: unknown) => encryptionMock(config),
}))

const fakeClient = { from: () => ({}) } as unknown as SupabaseClientLike

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  age: types.IntegerOrd('age'),
})

beforeEach(() => {
  introspectMock.mockReset().mockResolvedValue({
    tables: [],
    unmodelled: new Map(),
    eqlVersion: null,
  })
  encryptionMock.mockReset().mockResolvedValue({})
  delete process.env.DATABASE_URL
})
afterEach(() => vi.restoreAllMocks())

async function declaredClient() {
  const { encryptedSupabase } = await import('../src/index')
  return encryptedSupabase(fakeClient, { schemas: { users } })
}

describe('declared-schemas mode', () => {
  it('constructs with no database URL and never introspects', async () => {
    const client = await declaredClient()
    expect(client).toBeDefined()
    // The whole point: no connection was opened, so `pg` was never needed.
    expect(introspectMock).not.toHaveBeenCalled()
    expect(encryptionMock).toHaveBeenCalledTimes(1)
  })

  it('builds the encryption client from the declared tables', async () => {
    await declaredClient()
    const passed = encryptionMock.mock.calls[0][0] as {
      schemas: Array<{ tableName: string }>
    }
    expect(passed.schemas.map((t) => t.tableName)).toEqual(['users'])
  })

  it('still demands a URL when nothing is declared', async () => {
    const { encryptedSupabase } = await import('../src/index')
    await expect(encryptedSupabase(fakeClient)).rejects.toThrow(/DATABASE_URL/)
    expect(introspectMock).not.toHaveBeenCalled()
  })

  /**
   * The migration path for existing `schemas`-passing callers: the gate is the
   * database URL, not the absence of `schemas`. Passing both keeps the drift
   * check that verifies a declaration against the database.
   */
  it('still introspects when a URL is supplied alongside schemas', async () => {
    const { encryptedSupabase } = await import('../src/index')
    introspectMock.mockResolvedValue({
      tables: [
        {
          tableName: 'users',
          columns: [
            { columnName: 'email', domainName: 'eql_v3_text_search' },
            { columnName: 'age', domainName: 'eql_v3_integer_ord' },
          ],
        },
      ],
      unmodelled: new Map(),
      eqlVersion: '3.0.4',
    })
    await encryptedSupabase(fakeClient, {
      databaseUrl: 'postgres://x',
      schemas: { users },
    })
    expect(introspectMock).toHaveBeenCalledWith('postgres://x')
  })

  /**
   * `allColumns` can only come from introspection. Without it a `*` cannot be
   * expanded, and an unexpanded `*` reaches PostgREST with no `::jsonb` casts —
   * every encrypted column would come back uncast. Refusing is fail-closed.
   */
  it("refuses select('*'), naming declared mode as the reason", async () => {
    const client = await declaredClient()
    expect(() =>
      (client as { from: (t: string) => { select: (c?: string) => unknown } })
        .from('users')
        .select('*'),
    ).toThrow(/does not support select\('\*'\)/)
  })

  it('refuses a bare select() the same way', async () => {
    const client = await declaredClient()
    expect(() =>
      (client as { from: (t: string) => { select: (c?: string) => unknown } })
        .from('users')
        .select(),
    ).toThrow(/does not support select\('\*'\)/)
  })

  it('serves an explicit column list', async () => {
    const client = await declaredClient()
    const builder = (
      client as { from: (t: string) => { select: (c?: string) => unknown } }
    )
      .from('users')
      .select('email, age')
    expect(builder).toBeDefined()
  })

  /**
   * With no introspection there is no table list to discover from, so every
   * table must be declared — and the error has to say that rather than blaming
   * an introspection pass that never ran.
   */
  it('throws for an undeclared table, blaming the declaration not introspection', async () => {
    const client = await declaredClient()
    expect(() =>
      (client as { from: (t: string) => unknown }).from('orders'),
    ).toThrow(/not in the `schemas` you declared/)
  })

  /**
   * `queryDomainsRequired` is normally derived from the installed EQL version,
   * which only introspection can read. With no reading, it is FORCED rather
   * than assumed absent — the fail-loud direction. On EQL >= 3.0.2 it is
   * simply correct; on an older install the operand cast fails visibly instead
   * of emitting an operator the database will not engage.
   */
  it('forces the query-domain requirement it can no longer detect', async () => {
    const client = await declaredClient()
    expect(() =>
      (
        client as {
          from: (t: string) => { matches: (c: string, v: string) => unknown }
        }
      )
        .from('users')
        .matches('email', 'alice'),
    ).toThrow(/EQL 3\.0\.2\+/)
  })

  /**
   * A stray ambient `DATABASE_URL` must not overrule an explicit declaration
   * (#708 review). On the edge entry it made construction throw "drop
   * databaseUrl" about an option the caller never passed; on Node it would
   * introspect and drift-verify a database the caller never named.
   */
  it('ignores an ambient DATABASE_URL when schemas are declared', async () => {
    process.env.DATABASE_URL = 'postgres://ambient'
    const { encryptedSupabase } = await import('../src/index')
    await encryptedSupabase(fakeClient, { schemas: { users } })
    expect(introspectMock).not.toHaveBeenCalled()
  })

  /**
   * ...but does not change mode in silence. A caller who passed `schemas` and
   * let `DATABASE_URL` supply the connection used to get a construction-time
   * throw when that variable went missing; without this warning they would now
   * get declared mode instead, and lose the drift check with nothing said.
   */
  it('warns that the declaration is unverified when DATABASE_URL was ignored', async () => {
    process.env.DATABASE_URL = 'postgres://ambient'
    const { logger } = await import('@cipherstash/stack/adapter-kit')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    const { encryptedSupabase } = await import('../src/index')
    await encryptedSupabase(fakeClient, { schemas: { users } })
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0][0]).toMatch(/NOT verified against the database/)
    expect(warn.mock.calls[0][0]).toMatch(/databaseUrl/)
  })

  /**
   * The regression the warning above actually exists for. A caller who was
   * already passing `schemas` while `DATABASE_URL` supplied the connection got
   * a construction-time throw when that variable went missing; now they get a
   * working client with no drift check. Nothing at construction distinguishes
   * that from a deliberate declared-mode client, so both are told — a warning
   * gated on the ambient value being PRESENT would stay silent in exactly this
   * case.
   */
  it('warns when no URL resolves at all, not just when one was ignored', async () => {
    const { logger } = await import('@cipherstash/stack/adapter-kit')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    const { encryptedSupabase } = await import('../src/index')
    // No DATABASE_URL anywhere — `beforeEach` deleted it.
    await encryptedSupabase(fakeClient, { schemas: { users } })
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0][0]).toMatch(/NOT verified against the database/)
    // ...and it must not claim an ambient URL was ignored when none existed.
    expect(warn.mock.calls[0][0]).not.toMatch(/DATABASE_URL is set/)
  })

  it('stays silent on an explicit databaseUrl, which introspects anyway', async () => {
    const { logger } = await import('@cipherstash/stack/adapter-kit')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    const { encryptedSupabase } = await import('../src/index')
    introspectMock.mockResolvedValue({
      tables: [
        {
          tableName: 'users',
          columns: [
            { columnName: 'email', domainName: 'eql_v3_text_search' },
            { columnName: 'age', domainName: 'eql_v3_integer_ord' },
          ],
        },
      ],
      unmodelled: new Map(),
      eqlVersion: '3.0.4',
    })
    await encryptedSupabase(fakeClient, {
      databaseUrl: 'postgres://x',
      schemas: { users },
    })
    expect(warn).not.toHaveBeenCalled()
  })

  it('diagnoses schemas that declare no encrypted columns', async () => {
    const { encryptedSupabase } = await import('../src/index')
    const empty = encryptedTable('empty', {})
    await expect(
      encryptedSupabase(fakeClient, { schemas: { empty } }),
    ).rejects.toThrow(/no encrypted columns/)
  })
})

/**
 * The edge entry, with an ambient `DATABASE_URL` present.
 *
 * These deliberately do NOT delete the variable. The rest of this file — and
 * the Deno e2e — pinned the ENVIRONMENT to keep declared mode working, which
 * routed around the coupling instead of testing it: a build that cannot
 * introspect was still resolving the ambient value, and the refusal keyed on
 * the resolved value rather than on what the caller passed. So a caller who
 * did exactly what the docs say (declare `schemas`, pass no `databaseUrl`)
 * failed to construct the moment something else set `DATABASE_URL` — which is
 * ordinary on any runtime exposing `process.env`, and is precisely the
 * variable a Supabase project has lying around (#708 review, James).
 *
 * The guarantee is "declared mode ignores an ambient URL on a build that
 * cannot use one", not "declared mode works when the environment is clean".
 */
describe('the edge entry with an ambient DATABASE_URL', () => {
  const edgeClient = () =>
    makeEncryptedSupabase(
      (async () => ({})) as never,
      // No introspector — exactly how `wasm-inline.ts` binds it.
      null,
    )

  it('constructs from declared schemas even when DATABASE_URL is set', async () => {
    process.env.DATABASE_URL = 'postgres://ambient'
    await expect(
      edgeClient()(fakeClient, { schemas: { users } }),
    ).resolves.toBeDefined()
  })

  /**
   * The refusal must key on the option the caller wrote. Firing on a resolved
   * ambient value produced an unactionable error: it told them to drop
   * `databaseUrl` and to declare `schemas` when they had already done both.
   */
  it('still refuses a databaseUrl the caller actually passed', async () => {
    process.env.DATABASE_URL = 'postgres://ambient'
    await expect(
      edgeClient()(fakeClient, {
        databaseUrl: 'postgres://explicit',
        schemas: { users },
      }),
    ).rejects.toThrow(/cannot introspect/)
  })

  /**
   * With nothing declared the edge entry has no way to discover columns, and
   * the error must not send the caller to an environment variable this build
   * cannot read.
   */
  it('names the real fix when nothing is declared, not DATABASE_URL', async () => {
    process.env.DATABASE_URL = 'postgres://ambient'
    await expect(edgeClient()(fakeClient, {})).rejects.toThrow(
      /cannot introspect, so it has no way to discover/,
    )
    await expect(edgeClient()(fakeClient, {})).rejects.not.toThrow(
      /set the DATABASE_URL environment variable/,
    )
  })

  it('does not warn about an ambient URL it never consulted', async () => {
    process.env.DATABASE_URL = 'postgres://ambient'
    const { logger } = await import('@cipherstash/stack/adapter-kit')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {})
    await edgeClient()(fakeClient, { schemas: { users } })
    expect(warn).not.toHaveBeenCalled()
  })
})

describe('constructing where there is no `process` global', () => {
  /**
   * On Workers, Deno isolates and Edge Functions `process` is not defined, and
   * a bare `process.env.X` is a ReferenceError rather than `undefined`. The
   * unguarded read would therefore throw during construction, before declared
   * mode could make the connection unnecessary — the same defect class the
   * adapter-kit logger carried (#799).
   */
  it('does not read `process` unguarded', async () => {
    const original = globalThis.process
    // @ts-expect-error — deleting a global is the point of the test.
    delete globalThis.process
    try {
      const { encryptedSupabase } = await import('../src/index')
      await expect(
        encryptedSupabase(fakeClient, { schemas: { users } }),
      ).resolves.toBeDefined()
    } finally {
      globalThis.process = original
    }
  })
})
