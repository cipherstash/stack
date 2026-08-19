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
import { encryptedTable, types } from '@cipherstash/stack/wasm-inline'
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

/**
 * A Supabase client stand-in. The point of this test is CONSTRUCTION and
 * operand encryption, neither of which sends a request — so a real Supabase
 * project would add a network dependency without adding evidence. Anything
 * that did reach the network would fail loudly on the missing methods.
 */
function fakeSupabaseClient() {
  return {
    from() {
      throw new Error(
        'the fake Supabase client was queried — this test should not reach the network',
      )
    },
  }
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

    // Deliberately NOT set. Declared mode must not reach for it, and on this
    // runtime there is no Postgres to reach even if it did.
    assertEquals(
      Deno.env.get('DATABASE_URL'),
      undefined,
      'DATABASE_URL must be unset — this test proves construction without one',
    )

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
