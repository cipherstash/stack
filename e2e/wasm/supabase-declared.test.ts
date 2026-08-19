/**
 * WASM smoke test for `@cipherstash/stack-supabase/wasm-inline` (#708).
 *
 * `encryptedSupabase` used to be unconstructible off Node for two independent
 * reasons: it statically imported the native engine, and it always introspected
 * the database over a direct Postgres connection. Fixing either alone leaves
 * the wrapper broken, and neither failure is visible from a Node test — both
 * resolve perfectly there.
 *
 * So this runs the real thing on a real edge runtime. Under Deno, with no FFI
 * permission and no database anywhere, it proves:
 *   1. The `/wasm-inline` subpath resolves and its whole module graph loads —
 *      no `@cipherstash/protect-ffi` native binding, no `pg`.
 *   2. `encryptedSupabase` CONSTRUCTS from declared `schemas` alone, with no
 *      `databaseUrl` and no Postgres reachable. This is the headline of #708.
 *   3. The construction really did build a working encryption client: a query
 *      operand encrypts through it, via WASM.
 *   4. The things declared mode gives up, it gives up LOUDLY — `select('*')`
 *      is refused rather than silently emitting an uncast star, and an
 *      undeclared table is refused rather than silently passed through.
 *
 * No `--allow-ffi`. If the native binding were ever reached, the process would
 * fail on a missing FFI permission rather than quietly succeeding — that is
 * the WASM guarantee, same as `roundtrip.test.ts`.
 *
 * FAILS LOUDLY when any CS_* env var is missing: a silently-skipped credential
 * suite reads as green coverage that never ran.
 */

import {
  assertEquals,
  assertExists,
  assertThrows,
} from 'jsr:@std/assert@^1.0.0'
import {
  Encryption,
  encryptedTable,
  types,
} from '@cipherstash/stack/wasm-inline'
import { encryptedSupabase } from '@cipherstash/stack-supabase/wasm-inline'

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
    throw new Error(
      `Missing required env: ${missing.join(', ')}. This suite needs real ` +
        'CipherStash credentials — export the four CS_* variables (or put them ' +
        'in a repo-root .env; see AGENTS.md "Environment variables") or run ' +
        'via the CI job, which injects them.',
    )
  }
  return values
}

type RecordedCall = { method: string; args: unknown[] }

/**
 * A recording Supabase client stand-in.
 *
 * The evidence this file exists for is what the ADAPTER does — encrypt an
 * operand through WASM, emit it on the wire, decrypt the rows back — none of
 * which needs a live Supabase project. A real project would add a network
 * dependency and a second set of credentials without adding evidence, and
 * would hide the operand behind a round trip instead of handing it to us.
 *
 * So: record every builder call, and resolve to whatever rows the test wants
 * to hand back for decryption.
 */
function recordingSupabaseClient(resultData: unknown = []) {
  const calls: RecordedCall[] = []
  // biome-ignore lint/suspicious/noExplicitAny: test double standing in for the supabase query builder, whose chainable surface is ~25 methods
  // deno-lint-ignore no-explicit-any
  const qb: any = {}
  for (const method of [
    'select',
    'insert',
    'update',
    'upsert',
    'delete',
    'eq',
    'neq',
    'gt',
    'gte',
    'lt',
    'lte',
    'in',
    'is',
    'or',
    'match',
    'order',
    'limit',
    'range',
    'single',
    'maybeSingle',
    'filter',
    'not',
    'throwOnError',
    'abortSignal',
  ]) {
    qb[method] = (...args: unknown[]) => {
      calls.push({ method, args })
      return qb
    }
  }
  qb.then = (
    onfulfilled?: ((value: unknown) => unknown) | null,
    onrejected?: ((reason: unknown) => unknown) | null,
  ) =>
    Promise.resolve({
      data: resultData,
      error: null,
      count: null,
      status: 200,
      statusText: 'OK',
    }).then(onfulfilled, onrejected)

  return {
    client: { from: (_table: string) => qb },
    calls,
    callsFor: (method: string) => calls.filter((c) => c.method === method),
  }
}

/** The unused stand-in for tests that never reach a query. */
function fakeSupabaseClient() {
  return recordingSupabaseClient().client
}

Deno.test({
  name: 'stack-supabase/wasm-inline: constructs from declared schemas, no database, no native binding',
  permissions: {
    env: true,
    net: true,
    read: true,
    sys: true,
    // No FFI permission — see the file header.
    ffi: false,
  },
  async fn() {
    const env = requireEnv()

    assertExists(globalThis.WebAssembly, 'WebAssembly global missing')
    assertExists(
      globalThis.Deno,
      'Deno global missing (test framework misconfigured)',
    )

    // SET, deliberately. An earlier version of this test asserted the
    // variable was UNSET, which pinned the environment rather than the
    // behaviour — and routed around the very coupling that mattered: the edge
    // entry used to resolve the ambient value despite having no way to use it,
    // so a caller who declared `schemas` and passed no `databaseUrl` failed to
    // construct the moment something else set `DATABASE_URL`. Deno exposes
    // `process.env`, and `DATABASE_URL` is exactly the variable a Supabase
    // project has lying around, so this is the ordinary case rather than an
    // exotic one (#708 review, James).
    Deno.env.set('DATABASE_URL', 'postgres://ambient-should-be-ignored/db')

    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
      age: types.IntegerOrd('age'),
    })

    // The headline assertion of #708: this call previously could not be made
    // off Node at all. No `databaseUrl`, so nothing introspects.
    const supabase = await encryptedSupabase(
      fakeSupabaseClient() as never,
      {
        schemas: { users },
        config: {
          workspaceCrn: env.CS_WORKSPACE_CRN,
          accessKey: env.CS_CLIENT_ACCESS_KEY,
          clientId: env.CS_CLIENT_ID,
          clientKey: env.CS_CLIENT_KEY,
        },
      } as never,
    )
    assertExists(supabase, 'encryptedSupabase returned nothing')

    // Constructing is necessary but not sufficient: a wrapper that built a
    // broken encryption client would still get this far. Reaching a builder
    // for the declared table proves the schema survived construction.
    const builder = (
      supabase as unknown as {
        from: (t: string) => { select: (c?: string) => unknown }
      }
    ).from('users')
    assertExists(builder, 'from() on a declared table returned nothing')

    // Declared mode has no introspected column list, so `*` cannot be expanded
    // into the `::jsonb` casts encrypted columns need. It must refuse rather
    // than emit an uncast star.
    assertThrows(
      () => builder.select('*'),
      Error,
      "does not support select('*')",
    )

    // A bare select() is the same request spelled differently, and must fail
    // the same way.
    assertThrows(() => builder.select(), Error, "does not support select('*')")

    // With no introspection there is no table list to fall back on, so an
    // undeclared table is an error — and the message must blame the
    // declaration, not an introspection pass that never ran.
    assertThrows(
      () =>
        (supabase as unknown as { from: (t: string) => unknown }).from(
          'orders',
        ),
      Error,
      'not in the `schemas` you declared',
    )

    Deno.env.delete('DATABASE_URL')
  },
})

/**
 * The assertion the file header's point 3 promises, and the one that actually
 * exercises the WASM engine through the adapter (#708 review, finding 6).
 *
 * Construction proves the module graph loads. It does NOT prove the adapter
 * reconciled the two engines' protocols — the WASM client returns plain
 * Results rather than chainable operations, and its `decryptModel` REQUIRES
 * the table the native one derives from the payloads. Both differences are
 * silent until a query runs, so a query has to run here or the regression
 * lands in a customer's Edge Function.
 */
Deno.test({
  name: 'stack-supabase/wasm-inline: encrypts a filter operand and decrypts rows, through WASM',
  permissions: {
    env: true,
    net: true,
    read: true,
    sys: true,
    ffi: false,
  },
  async fn() {
    const env = requireEnv()

    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })

    const config = {
      workspaceCrn: env.CS_WORKSPACE_CRN,
      accessKey: env.CS_CLIENT_ACCESS_KEY,
      clientId: env.CS_CLIENT_ID,
      clientKey: env.CS_CLIENT_KEY,
    }

    // Encrypt a value up front so the row handed back to the decrypt path is a
    // real EQL payload rather than a fixture — a fake would prove nothing
    // about the adapter's decrypt half.
    const engine = await Encryption({ schemas: [users], config })
    const plaintext = `wasm-supabase-${crypto.randomUUID()}@example.com`
    const encrypted = await engine.encrypt(plaintext, {
      column: users.email,
      table: users,
    })
    if (encrypted.failure) {
      throw new Error(`setup encrypt failed: ${encrypted.failure.message}`)
    }

    const { client, callsFor } = recordingSupabaseClient([
      { email: encrypted.data },
    ])

    const supabase = await encryptedSupabase(client as never, {
      schemas: { users },
      config,
    })

    // ENCRYPT half: the filter operand must reach the wire encrypted. If the
    // adapter's `encrypt` were wrong, this throws rather than silently sending
    // plaintext — but assert on the operand anyway, because "did not throw" is
    // not the same as "did not leak".
    const rows = await (
      supabase as unknown as {
        from: (t: string) => {
          select: (c: string) => {
            eq: (c: string, v: string) => PromiseLike<{ data: unknown }>
          }
        }
      }
    )
      .from('users')
      .select('email')
      .eq('email', plaintext)

    const eqCalls = callsFor('eq')
    assertEquals(eqCalls.length, 1, 'expected exactly one eq() on the wire')
    const operand = eqCalls[0].args[1]
    assertEquals(
      typeof operand === 'string' && operand.includes(plaintext),
      false,
      'the filter operand reached PostgREST as plaintext',
    )
    assertExists(operand, 'no filter operand was emitted')

    // DECRYPT half: the row came back as a real EQL payload, and the adapter
    // had to supply the table the WASM client requires. Without that this
    // throws — which is the whole point of the adapter.
    const data = (rows as { data: Array<{ email: unknown }> }).data
    assertEquals(data.length, 1, 'expected one decrypted row')
    assertEquals(
      data[0].email,
      plaintext,
      'the row did not decrypt back to the original plaintext',
    )
  },
})

/**
 * Deliberately credential-free.
 *
 * The refusal happens while resolving options, long before any encryption
 * client is built, so requiring credentials here would gate a real assertion
 * on a secret it does not use — and make this the one part of #708's evidence
 * that cannot be reproduced outside CI. Loading the module graph at all is
 * itself the other half of what this file proves.
 */
Deno.test({
  name: 'stack-supabase/wasm-inline: refuses a databaseUrl it cannot honour',
  permissions: { env: true, net: true, read: true, sys: true, ffi: false },
  async fn() {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })

    // The edge entry carries no Postgres driver. Passing `databaseUrl` must
    // say so, rather than silently ignoring the option or failing later with
    // an unresolvable module.
    let message = ''
    try {
      await encryptedSupabase(
        fakeSupabaseClient() as never,
        {
          databaseUrl: 'postgres://nowhere/db',
          schemas: { users },
        } as never,
      )
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }
    assertEquals(
      message.includes('cannot introspect'),
      true,
      `expected the edge entry to refuse databaseUrl, got: ${message || '(no error)'}`,
    )
  },
})
