import { Encryption } from '@cipherstash/stack'
import type { EncryptionFactory } from './create'
import { makeEncryptedSupabase } from './create'
import { eqlRequiresQueryDomains, introspect } from './introspect'

/**
 * The default (Node) entry.
 *
 * Binds the factory to `Encryption` from the native `@cipherstash/stack`
 * entry. That import is static and top-level, so the engine's whole module
 * graph evaluates on import of this module whether or not any encryption runs
 * — and that graph statically imports `@cipherstash/auth`, whose Node entry
 * resolves its platform binding at module evaluation. On Deno, Supabase Edge
 * Functions or Cloudflare Workers it fails there, before any of this package's
 * own code. Import `@cipherstash/stack-supabase/wasm-inline` instead on those
 * runtimes (#708).
 *
 * Not `@cipherstash/protect-ffi`, the graph's other Node-API package: it
 * deliberately resolves nothing until first use — see
 * `packages/protect-ffi/src/index.cts` and the `nativeLoading.test.ts` beside
 * it. And the engine is not the only thing pinning this entry to Node: its own
 * emitted bundle carries an `import("pg")` specifier for introspection, which
 * a bundler resolves at build time. `__tests__/wasm-entry-edge-safety.test.ts`
 * asserts both against the emitted files.
 */
export const encryptedSupabase = makeEncryptedSupabase(
  // biome-ignore lint/plugin: `EncryptionFactory` names only the shape `construct` uses; the native factory's real signature is a generic tuple overload that cannot be expressed as a plain function type without re-declaring it here.
  Encryption as unknown as EncryptionFactory,
  { introspect, eqlRequiresQueryDomains },
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
