/**
 * Regression guard for the public `@cipherstash/stack/types` entrypoint
 * (`src/types-public.ts`).
 *
 * That file is a hand-maintained allowlist of `export type { … } from '@/types'`.
 * Nothing derives it and nothing checks it, so its contents drift by a one-line
 * edit in either direction — and both directions are silent:
 *
 * - REMOVING a name breaks consumers who legitimately need to NAME a type that
 *   appears in a public signature (declaring a variable before the `await`,
 *   typing an adapter's parameter). `@cipherstash/stack-drizzle`,
 *   `@cipherstash/stack-supabase` and `@cipherstash/stack-prisma` all import from
 *   this subpath.
 * - ADDING a name is how the EQL v2 authoring surface comes back. `src/types.ts`
 *   still declares v2-shaped types — the client must keep DECRYPTING v2 payloads,
 *   so the v2 builders survive as internals — and they sit in the same module the
 *   allowlist re-exports from. Publishing one is a single line.
 *
 * Importing a name a module does not export fails typecheck, so both halves are
 * expressible here: the positive block compiling proves the surface is intact,
 * and each `@ts-expect-error` failing to find an error proves a v2 name leaked
 * back onto it. Run with `pnpm --filter @cipherstash/stack test:types`.
 *
 * The predecessor of this file was deleted alongside the v2 authoring surface in
 * `a3830f0d` (#815) and not replaced, which left `./types` with no guard at all.
 */

import { describe, expectTypeOf, it } from 'vitest'
import type {
  AuthStrategy,
  ClientConfig,
  Decrypted,
  Encrypted,
  EncryptedQueryResult,
  EncryptionClientConfig,
  EncryptOptions,
  EncryptQueryOptions,
  QueryTypeName,
  ScalarQueryTerm,
} from '@/types-public'
import { queryTypes } from '@/types-public'

// ---------------------------------------------------------------------------
// The v2 residue that must NOT be re-exported.
//
// Each directive below is load-bearing in the unusual direction: it fails when
// there is NO error, i.e. when the name HAS become public again. These are the
// exact specifiers `a3830f0d` deleted from the allowlist.
//
// They are written as `import(...)` type nodes rather than
// `export type { X } from '@/types-public'` on purpose: Biome's formatter merges
// adjacent re-exports of the same module into one statement, which would collapse
// all three onto a single line under a single directive. One directive covering
// three specifiers is satisfied by ANY one of them erroring, so two names could
// leak back with the guard still green. One declaration per name keeps the
// directives one-to-one.
// ---------------------------------------------------------------------------

// `BuildableQueryColumn`'s first arm is the v2 `EncryptedColumn` class (see
// `src/types.ts`). It stays internal: it is the parameter type of the
// `inferIndexType` / `validateIndexType` helpers, which are still exercised
// against v2 columns, but nothing public should be able to name a union with a
// v2 builder in it.
// @ts-expect-error - v2 residue, internal-only
export type NoQueryColumnArm = import('@/types-public').BuildableQueryColumn

// `EncryptedFromSchema` keys entirely off `EncryptedColumn | EncryptedField` —
// the v2 builders — so it is meaningless for a v3 schema. The v3 equivalent is
// `EncryptedFromBuildableTable`, also internal.
//
// The type arguments are REQUIRED for this guard to discriminate. Written bare,
// the reference errors with "requires 2 type argument(s)" whether or not the
// name is exported, so the directive is always consumed and the assertion is
// vacuous — it passed while the name was public. Applying the type arguments
// leaves TS2694 ("no exported member") as the only possible error.
// @ts-expect-error - v2-only model mapper, internal-only
export type NoV2ModelMapper = import('@/types-public').EncryptedFromSchema<
  unknown,
  never
>

// `SearchTerm` is the v2-era spelling of a query term (it carries
// `BuildableQueryColumn` directly); `ScalarQueryTerm` is the shape `encryptQuery`
// actually takes and is the one exported above.
// @ts-expect-error - superseded by ScalarQueryTerm, internal-only
export type NoV2SearchTerm = import('@/types-public').SearchTerm

describe('public @cipherstash/stack/types surface', () => {
  it('keeps the config types nameable', () => {
    // Adapters declare these before they have a client. `ClientConfig` must not
    // collapse to `never` — `eqlVersion?: never` on a v3-only config makes an
    // over-eager narrowing plausible.
    expectTypeOf<ClientConfig>().not.toBeNever()
    expectTypeOf<EncryptionClientConfig>().not.toBeNever()
    expectTypeOf<AuthStrategy>().not.toBeNever()
  })

  it('keeps the payload and model types nameable', () => {
    expectTypeOf<Encrypted>().not.toBeNever()
    expectTypeOf<
      Decrypted<{ email: Encrypted }>['email']
    >().toEqualTypeOf<string>()
  })

  it('keeps the encryptQuery option and result types nameable', () => {
    // The types on `encryptQuery`'s public signature. A caller building terms in
    // a helper function has to name these.
    expectTypeOf<EncryptOptions>().not.toBeNever()
    expectTypeOf<EncryptQueryOptions>().not.toBeNever()
    expectTypeOf<ScalarQueryTerm>().toMatchTypeOf<EncryptQueryOptions>()
    expectTypeOf<EncryptedQueryResult>().not.toBeNever()
  })

  it('exports queryTypes as a runtime value whose keys are QueryTypeName', () => {
    // Referenced as a VALUE (not `typeof`) so this stays a runtime import under
    // `verbatimModuleSyntax` — `./types` is the only entry that publishes it.
    expectTypeOf(queryTypes.equality).toEqualTypeOf<'equality'>()
    expectTypeOf<keyof typeof queryTypes>().toEqualTypeOf<QueryTypeName>()
  })
})
