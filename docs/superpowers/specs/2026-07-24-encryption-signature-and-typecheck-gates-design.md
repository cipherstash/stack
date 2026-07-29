# `Encryption` signature fixes and typecheck gates

**Date:** 2026-07-24
**Branch:** `fix/encryption-signature-and-typecheck-gates` (off `8b3f0b15`)
**Addresses:** A-4, A-6, A-7, C-1 from `.work/2026-07-24-eql-v2-removal-verification.md`
**Issue:** #778 (review remediation for #772)

## Why these four, and why not more

A-6 and A-7 exist because `Encryption` is overloaded, and it is overloaded because there
are two kinds of client: the typed EQL v3 one and the nominal one that EQL v2 and loose
introspection-derived schemas need. Two overloads means two discriminators that can
disagree — overload resolution reads the `config` argument, the runtime reads the
`schemas` argument (`encryption/index.ts:947`). Remove EQL v2 and there is one client,
one signature, and both defects delete themselves.

So this change deliberately does **not** attempt the type-level repair the verification
doc explores (a single generic signature returning `ClientFor<S, C>`, a discriminated-union
`WireConfig`, `ConfigFor<S>`). That machinery exists only to make two clients coexist
safely, and it would be deleted by the v2 removal that motivates it. It is issue #637 and
it belongs with PRs 9–12.

What is left is the subset that is either independent of the v2 removal (A-4, C-1) or
cheap and non-throwaway (A-6, A-7).

## A-4 — non-tuple schema arrays are rejected

### Problem

`Encryption({ schemas })` accepts only an array *literal*. Every indirect form fails with
`TS2769`:

```ts
export const all: AnyV3Table[] = [users, orders]   // shared module
await Encryption({ schemas: all })                 // TS2769
```

Also broken: `ReadonlyArray<AnyV3Table>` (the type `prisma-next` exposes publicly),
push-built arrays, spreads, and unannotated `const all = [...]`.

The constraint at `encryption/index.ts:872-877` is a non-empty *tuple*:

```ts
export function Encryption<
  const S extends readonly [AnyV3Table, ...AnyV3Table[]],
>(config: { schemas: S; config?: V3ClientConfig }): Promise<TypedEncryptionClient<S>>
```

It was narrowed to a tuple by `7e0092f3` for one reason: `readonly AnyV3Table[]` admits
`readonly []`, so `Encryption({ schemas: [] })` type-checked and then threw at runtime.

This is a live break on a released surface. `prisma-next` already had to work around it
with a destructure-and-respread through three coupled edits in `from-stack-v3.ts`; any
customer with schema-building indirection hits the same wall.

### Design

Widen the type parameter to the array and move the non-emptiness check to the property, so
`[]` is rejected without the tuple constraining every other form:

```ts
type NonEmptyV3<S extends readonly AnyV3Table[]> = S['length'] extends 0 ? never : S

export function Encryption<const S extends readonly AnyV3Table[]>(config: {
  schemas: NonEmptyV3<S>
  config?: V3ClientConfig
}): Promise<TypedEncryptionClient<S>>
```

`schemas` must resolve through `NonEmptyV3<S>` rather than being wrapped in a conditional
alias applied to the whole config — wrapping defeats `const` inference and degrades the
tuple to an array, losing per-column typing on the literal path.

The runtime throw at `encryption/index.ts:891` stays as the backstop for JavaScript callers.

### Acceptance

A `.test-d.ts` probe pinning both directions:

- compile: inline literal, shared `AnyV3Table[]`, `ReadonlyArray<AnyV3Table>`, push-built,
  spread, unannotated `const`;
- still error: `{ schemas: [] }`, wrong plaintext type for a column's domain, a table that
  is not a member of the registered tuple.

## A-6 — `ReturnType<typeof Encryption>` resolves to the nominal client

### Problem

TypeScript's `ReturnType` reads the *last* overload, which is the nominal one. So
`Awaited<ReturnType<typeof Encryption>>` yields `EncryptionClient` even for an all-v3
schema set, and assigning the real client to it fails:

```text
Type 'TypedEncryptionClient<…>' is missing the following properties
from type 'EncryptionClient': client, encryptConfig, init
```

Overload order cannot fix this — whichever signature is last wins, so one of the two forms
is always mis-resolved. Reordering additionally destroys the typed client, because a v3
table structurally satisfies `BuildableTable` and so matches the nominal overload.

This is a regression from the released surface, not a pre-existing wart: all 15 instances
were introduced by `d7ff8471`, which turned a single-signature `EncryptionV3` into an alias
of an overloaded `Encryption`. `packages/bench/src/drizzle/setup.ts:38-45` already carries a
hand-rolled workaround.

15 sites, none visible to CI:

| Package | Sites |
|---|---|
| `packages/stack` | `__tests__/dynamodb/encrypted-dynamodb-v3.test.ts` (×3), `__tests__/encrypt-lock-context-guards.test.ts`, `__tests__/encrypt-query-searchable-json.test.ts`, `__tests__/encrypt-query-stevec.test.ts`, `integration/shared/{matrix-crypto,matrix-sql,schema-pg,schema-v3-client}.integration.test.ts` |
| `packages/stack-drizzle` | `integration/{adapter,json-adapter}.ts`, `integration/{lock-context,null-persistence,relational}.integration.test.ts` |

### Design

No signature change. `EncryptionClientFor<S>` (`encryption/v3.ts:399-402`) already exists and
is the correct idiom — the prior-art survey in the verification doc found that no library
dispatches a schema-dependent result type through `ReturnType`; they all expose a named
extraction type (`z.infer`, `typeof x.infer`, hono's `Client<T>`). Convert the call sites to
it and document it as *the* way to name the client.

**`EncryptionClientFor` must be widened in step with A-4.** It carries the same narrow tuple
guard:

```ts
S extends readonly [AnyV3Table, ...AnyV3Table[]] ? TypedEncryptionClient<S> : EncryptionClient
```

Left alone, `EncryptionClientFor<readonly AnyV3Table[]>` falls through to `EncryptionClient` —
so the type A-6 tells callers to use would silently hand back the nominal client for exactly
the non-tuple schemas A-4 just enabled. It becomes:

```ts
export type EncryptionClientFor<S extends readonly unknown[]> =
  S extends readonly AnyV3Table[]
    ? S['length'] extends 0
      ? EncryptionClient
      : TypedEncryptionClient<S>
    : EncryptionClient
```

The `readonly []` arm must be checked *inside* the v3 branch and before the tuple is used:
`never extends X` is true, so an empty tuple otherwise satisfies "all elements are v3".

Erased sites that pass `[schema as never]` (the generic `stack-drizzle` integration adapters)
are declared `EncryptionClientFor<readonly AnyV3Table[]>`, which resolves to
`TypedEncryptionClient<readonly AnyV3Table[]>` and accepts `TypedEncryptionClient<readonly [never]>`
by method bivariance.

`encryption-overloads.test-d.ts:84-88` currently asserts the defect as expected behaviour and
is green in CI. It is rewritten to assert `EncryptionClientFor<S>` resolves correctly instead.

## A-7 — the type says nominal, the runtime hands back typed

### Problem

Overload resolution matches on the `config` argument; the runtime picks its client by
inspecting the `schemas` (`encryption/index.ts:947`, `isV3Only && eqlVersion === 3`). They
disagree whenever a config is hoisted into a `ClientConfig`-typed variable:

```ts
const cfg: ClientConfig = {}                       // not assignable to V3ClientConfig
const c = await Encryption({ schemas: [users], config: cfg })
// type: EncryptionClient   runtime: TypedEncryptionClient
c.init(...)  // TypeError: init is not a function
```

`ClientConfig.eqlVersion` is `2 | 3`; the v3 overload requires `eqlVersion?: 3`. So the
variable form selects the nominal overload while the runtime still returns the typed client.
This bites whenever the variable's runtime `eqlVersion` is anything but `2` — `{}`,
`{ keyset }`, `{ authStrategy }`: the common case.

Measured blast radius: `init` is the **only** member on `EncryptionClient.prototype` absent
from the typed client at runtime. The other ten are all present.

### Design

Add an `init` passthrough to the object `typedClient()` returns, declared `@internal` on
`TypedEncryptionClient` so `satisfies` still checks the shape:

```ts
init: (config) => client.init(config),
```

This reduces the runtime gap to zero. What remains is a silent capability downgrade — the
type says nominal, so the caller loses the typed surface with no diagnostic. No type-level
design closes that: the runtime inspects values while the type inspects an erasable static
type. It ends when v2 removal collapses the two clients into one.

### Acceptance

A unit test reproducing the exact shape (config declared `ClientConfig`, v3 schemas,
`EncryptionClient.prototype.init` stubbed so no credentials are needed) that fails with
`TypeError: client.init is not a function` before the change and passes after.

## C-1 — typecheck gates

### Problem

The root `typecheck` gate for `examples/*` already exists (`.github/workflows/tests.yml:155-161`,
added by `5fab1cf6`) — the verification doc refutes the original framing. The remaining gap is
the surfaces nothing typechecks at all.

Measured after a full `pnpm run build` (most apparent failures were unbuilt workspace deps
resolving to `dist/*.d.ts`, not real errors):

| Surface | Errors | Has script |
|---|---|---|
| `packages/bench` | 0 | no |
| `packages/migrate` | 0 | no |
| `packages/prisma-next` | 0 | `typecheck` |
| `packages/test-kit` | 0 | `test:types` |
| `packages/wizard` | 0 | `typecheck` |
| `examples/basic` | 0 | `typecheck` (gated) |
| `examples/prisma` | 0 | `typecheck` (never invoked) |
| `e2e` | 0 | no |
| `packages/nextjs` | 2 | no |
| `packages/stack-supabase` | 11 | `test:types` (narrower config) |
| `packages/cli` | 21 | no |
| `packages/stack-drizzle` | 69 | `test:types` (narrower config) |
| `packages/stack` | 168 | `test:types` (narrower config) |

The three `test:types` scripts run `vitest --typecheck.only` against a `tsconfig.typecheck.json`
whose `include` is `__tests__/**/*.test-d.ts` — so the package's real `tsconfig.json`, which
covers `src`, `__tests__/**/*.test.ts` and `integration/**`, is never checked.

### Design

Gate what is green, and record what is not with its count rather than silently skipping it.

1. Add `typecheck` scripts (`tsc --noEmit -p tsconfig.json`) to `bench`, `migrate`, `nextjs`,
   `e2e`; keep the existing ones on `prisma-next`, `wizard`, `examples/*`.
2. One CI job running the eight green surfaces plus `nextjs`, after `pnpm run build` (they
   resolve workspace deps through `dist/*.d.ts`).
3. Fix `packages/nextjs`'s 2 errors: `vi.Mock` is used as a *type* in
   `__tests__/nextjs.test.ts:68,81`; it needs `import type { Mock } from 'vitest'`.
4. Add `"outputs": ["dist/**"]` to `turbo.json`'s `build` task. It currently declares none,
   so a cached build restores nothing and the `examples/basic` gate — which typechecks
   against `packages/stack/dist/*.d.ts` — holds today only because fresh CI runners have no
   cache.
5. Record `stack-supabase` (11), `cli` (21), `stack-drizzle` (69), `stack` (168) as
   documented follow-ups.

### Deliberately out of scope

Making `stack`, `stack-drizzle`, `stack-supabase` and `cli` green. 51 of `stack-drizzle`'s 69
and all 11 of `stack-supabase`'s are one root cause — `spec.indexes.unique` / `.ore` / `.ope`
against `V3_MATRIX` in `packages/test-kit`'s catalog, where `typedEntries` collapses the spec
to a union whose members do not all carry those keys. A single fix in `test-kit` likely clears
~62 of the ~80 errors across those two packages. That is the highest-leverage next step and it
is its own change.

## Interactions and ordering

A-4 and A-6 must land together: widening `Encryption` without widening `EncryptionClientFor`
leaves the documented idiom resolving to the wrong client.

A-7 is independent but shares the same files, and it removes `init` from A-6's `TS2739`
message (leaving only the private `client` / `encryptConfig` fields), so it lands first to
keep the A-6 diffs legible.

C-1 is independent of all three. It is sequenced last because the A-6 conversions remove 15
of the errors in the two packages it reports counts for.

## Other deliverables

- Changeset: `@cipherstash/stack` **minor** — A-4 widens a released signature and A-7 adds a
  member to `TypedEncryptionClient`. `@cipherstash/stack-drizzle` patch for the integration
  adapter conversions.
- Delete the migration paragraph in `.changeset/stack-audit-on-decrypt.md` telling callers to
  narrow `AnyV3Table[]` to `readonly [AnyV3Table, ...AnyV3Table[]]` — A-4 makes that advice
  obsolete, and it was never correct for `ReadonlyArray<AnyV3Table>` anyway.
- Skills sweep: `skills/stash-encryption/SKILL.md` for any `ReturnType<typeof Encryption>`
  guidance and for schema-array examples that the widening now permits.
- `packages/stack/README.md` and `packages/prisma-next` docs for the same.
