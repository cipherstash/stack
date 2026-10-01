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
 * - **`schemas` is required.** This entry cannot introspect, so a declaration is
 *   the only way to discover the encrypted columns. Omitting it is a type
 *   error, and a construction-time throw for callers arriving from plain JS —
 *   not a client that quietly encrypts nothing.
 * - **`config` is required, and is a `WasmClientConfig`.** There is no
 *   `~/.cipherstash` to discover credentials from on an edge runtime, so
 *   authentication is passed in: `clientId` and `clientKey` always, then
 *   either `workspaceCrn` + `accessKey` or a pre-built `authStrategy` (which
 *   carries the CRN itself). Typing it as the native (optional)
 *   `ClientConfig` let a caller omit it and reach a `TypeError` from inside the
 *   engine, and let native-only fields such as `keyset` type-check while being
 *   silently ignored.
 * - **`databaseUrl` is refused, and refused by the type.** Introspection is the
 *   thing this entry cannot do — it carries no Postgres driver — so the field
 *   is declared `never` rather than merely left out. Omission is policed by
 *   excess-property checking alone, which fires on FRESH object literals: an
 *   options object assembled as a `const` and passed by variable, which is what
 *   a Node → edge port actually holds, type-checked clean and then hit the
 *   runtime throw in `makeEncryptedSupabase`. Mirrors
 *   `WasmClientConfig.eqlVersion?: never` in `packages/stack/src/wasm-inline.ts`
 *   — same gap, same fix, one package along.
 */
export interface EncryptedSupabaseWasmOptions<S extends V3Schemas> {
  schemas: S
  config: WasmClientConfig
  /**
   * Declared only to be refused: this entry has no introspector to hand a
   * connection string to. The type is defence in depth, not a replacement for
   * the throw in `makeEncryptedSupabase` (`./create`), which is still the only
   * thing a plain JS caller meets — see the third bullet above for why both
   * are needed.
   *
   * As with `eqlVersion` on `WasmClientConfig`, `?: never` still admits an
   * explicit `databaseUrl: undefined` without `exactOptionalPropertyTypes` (not
   * enabled in this repo) and cannot be made to reject it. That is harmless
   * here: the runtime guard tests the VALUE, so `undefined` is exactly the case
   * it means to let through.
   */
  databaseUrl?: never
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
 * The engine is what made the default entry Node-only, and this entry does not
 * carry it. Introspection is a separate axis: this one cannot introspect at
 * all — it has no Postgres driver — so `schemas` is required rather than
 * optional. Declaring them on the DEFAULT entry drops introspection too, and
 * leaves that entry exactly as Node-bound as it was.
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
