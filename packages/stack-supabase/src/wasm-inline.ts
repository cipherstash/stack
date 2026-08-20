import type { WasmClientConfig } from '@cipherstash/stack/wasm-inline'
import { Encryption } from '@cipherstash/stack/wasm-inline'
import { makeEncryptedSupabase } from './create'
import type {
  SupabaseClientLike,
  TypedEncryptedSupabaseInstance,
  V3Schemas,
} from './types'
import { adaptWasmEncryption } from './wasm-client-adapter'

/**
 * Options for the edge entry.
 *
 * Three differences from the default entry's options, each one a runtime
 * requirement made visible to the type checker (#708 review):
 *
 * - **`schemas` is required.** This entry cannot introspect, so a client built
 *   without a declaration has no columns and nothing to encrypt.
 * - **`config` is required, and is a `WasmClientConfig`.** There is no
 *   `~/.cipherstash` to discover credentials from on an edge runtime, so all
 *   four `CS_*` values must be passed. Typing it as the native (optional)
 *   `ClientConfig` let a caller omit it and reach a `TypeError` from inside the
 *   engine, and let native-only fields such as `keyset` type-check while being
 *   silently ignored.
 * - **`databaseUrl` is absent.** Introspection is the thing this entry cannot
 *   do; the option is refused at runtime, and this stops it being written.
 */
export interface EncryptedSupabaseWasmOptions<S extends V3Schemas> {
  schemas: S
  config: WasmClientConfig
}

/**
 * The call shapes this entry accepts — deliberately narrower than the default
 * entry's, and declared here rather than reused so the requirements above are
 * enforced rather than described.
 */
export interface EncryptedSupabaseWasmFactory {
  <S extends V3Schemas>(
    supabaseUrl: string,
    supabaseKey: string,
    options: EncryptedSupabaseWasmOptions<S>,
  ): Promise<TypedEncryptedSupabaseInstance<S>>
  <S extends V3Schemas>(
    supabaseClient: SupabaseClientLike,
    options: EncryptedSupabaseWasmOptions<S>,
  ): Promise<TypedEncryptedSupabaseInstance<S>>
}

/**
 * The edge entry — same wrapper, WASM engine (#708).
 *
 * Identical to `@cipherstash/stack-supabase` in every respect except which
 * `Encryption` it binds: this one comes from `@cipherstash/stack/wasm-inline`,
 * which carries the engine as an inlined WASM blob and imports no native
 * binary, so the module graph loads on Deno, Supabase Edge Functions and
 * Cloudflare Workers.
 *
 * The engine is only half of what made the default entry Node-only; the other
 * half is introspection, which opens a Postgres connection. This entry cannot
 * introspect at all, so `schemas` is required rather than optional.
 *
 * The client is not passed through as-is: `adaptWasmEncryption` reconciles the
 * two engines' protocols, which differ in ways that are silent at construction
 * and only surface once a query runs. See that module for what differs.
 *
 * This entry is ESM-only, matching `@cipherstash/stack/wasm-inline`, and is
 * server-side: it is not browser-safe (#804).
 */
export const encryptedSupabase = makeEncryptedSupabase(
  adaptWasmEncryption(
    // biome-ignore lint/plugin: same reason as the native entry — the WASM factory's generic tuple overloads are not expressible as the plain function type the adapter takes.
    Encryption as unknown as Parameters<typeof adaptWasmEncryption>[0],
  ),
  // Deliberately none. `introspect` reaches `pg` through a dynamic import, and
  // a dynamic import is still a specifier in the bundle — statically importing
  // it here would put `import("pg")` into the edge build for a bundler to
  // resolve against a dependency this runtime will never have. Passing `null`
  // keeps it out of the graph, which `wasm-entry-edge-safety.test.ts` asserts
  // against the emitted file. Introspecting from a Worker over `pg-cloudflare`
  // is possible in principle and is not wired up here (#808).
  null,
) as EncryptedSupabaseWasmFactory

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
