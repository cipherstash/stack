import { Encryption } from '@cipherstash/stack/wasm-inline'
import type { EncryptionFactory } from './create'
import { makeEncryptedSupabase } from './create'

/**
 * The edge entry — same wrapper, WASM engine (#708).
 *
 * Identical to `@cipherstash/stack-supabase` in every respect except which
 * `Encryption` it binds: this one comes from `@cipherstash/stack/wasm-inline`,
 * which carries the engine as an inlined WASM blob and imports no native
 * binary, so the module graph loads on Deno, Supabase Edge Functions and
 * Cloudflare Workers.
 *
 * **Declare your schemas.** The engine is only half of what made the default
 * entry Node-only; the other half is introspection, which opens a Postgres
 * connection. Passing `schemas` skips it. Constructing this entry without
 * `schemas` still needs `databaseUrl`, and therefore still needs somewhere a
 * TCP socket to Postgres can be opened — which an edge runtime may or may not
 * offer, and the browser does not.
 *
 * This entry is ESM-only, matching `@cipherstash/stack/wasm-inline`, and is
 * server-side: it is not browser-safe (#804).
 */
export const encryptedSupabase = makeEncryptedSupabase(
  Encryption as unknown as EncryptionFactory,
  // Deliberately none. `introspect` reaches `pg` through a dynamic import, and
  // a dynamic import is still a specifier in the bundle — statically importing
  // it here would put `import("pg")` into the edge build for a bundler to
  // resolve against a dependency this runtime will never have. Passing `null`
  // keeps it out of the graph, which `wasm-entry-edge-safety.test.ts` asserts
  // against the emitted file. Introspecting from a Worker over `pg-cloudflare`
  // is possible in principle and is not wired up here (#808).
  null,
)

/**
 * @deprecated Use {@link encryptedSupabase}. `encryptedSupabaseV3` is a
 * type-identical alias kept for existing imports; the `V3` suffix is redundant
 * now that EQL v3 is the only generation this wrapper authors.
 */
export const encryptedSupabaseV3 = encryptedSupabase

export type {
  EncryptedQueryBuilder,
  EncryptedQueryBuilderCore,
  EncryptedQueryBuilderUntyped,
  // Deprecated `*V3` aliases (Decision 5 — supabase keeps type-identical aliases).
  EncryptedQueryBuilderV3,
  EncryptedQueryBuilderV3Untyped,
  EncryptedSingleQueryBuilder,
  EncryptedSupabaseError,
  EncryptedSupabaseInstance,
  EncryptedSupabaseOptions,
  EncryptedSupabaseResponse,
  EncryptedSupabaseV3Instance,
  EncryptedSupabaseV3Options,
  FilterableKeys,
  FreeTextSearchableKeys,
  PendingOrCondition,
  SupabaseClientLike,
  TypedEncryptedSupabaseInstance,
  TypedEncryptedSupabaseV3Instance,
  V3FilterableKeys,
  V3FreeTextSearchableKeys,
  V3Schemas,
} from './types'
