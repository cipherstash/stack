# Adapter package split — execution plan (#627)

Extract the Supabase and Drizzle integrations out of `@cipherstash/stack` into
their own packages (`@cipherstash/stack-supabase`, `@cipherstash/stack-drizzle`),
each depending on stack via `workspace:*`, following the `@cipherstash/prisma-next`
precedent. Tracked in #627; PR1's integration harness (#616) is merged, which is
the safety net this refactor wanted behind it.

## Status

- **DONE (committed on this branch):** the enabling support surface
  `@cipherstash/stack/adapter-kit` — a single narrow entry re-exporting exactly the
  core internals the adapters consume. Builds; all re-exported values resolve.
- **STAGED (this plan):** the mechanical move of the adapter code + tests into the
  two new packages. Deliberately left for an **attended** session — it touches
  ~35 files across a package boundary and each import rewrite / test move is a live
  breakage point best caught interactively, not overnight.

## The design decision (needs sign-off)

The plan's own risk note said the "expose internal modules vs relocate them" call
is *"a design call to make before coding."* Made here, defaulted to **expose**, and
kept as small and reversible as possible:

> Rather than leak six internal module paths (`@/utils/logger`,
> `@/encryption/helpers`, `@/encryption/operations/base-operation`,
> `@/eql/v3/columns`, `@/eql/v3/domain-registry`, `@/schema/match-defaults`) into
> the public surface, **one** new subpath — `@cipherstash/stack/adapter-kit` —
> re-exports exactly the symbols the adapters use. It is documented as the
> core↔first-party-adapter seam, not general-purpose public API.

The internal `@/types` symbols the adapters need (`BulkEncryptedData`,
`ClientConfig`, `Encrypted`, `QueryTypeName`, `queryTypes`) are **already** in the
public `./types` — so they need no new surface; the move repoints those imports to
`@cipherstash/stack/types`. `AnyEncryptedV3Column` is already in `./eql/v3`.

**If you'd rather relocate** (e.g. move `logger` to `@cipherstash/utils`, the v3
column/registry pieces to `@cipherstash/schema`) than expose `adapter-kit`, say so
and the move repoints accordingly — the mechanical steps below are unchanged.

## Verified import surface (what the adapters pull from core)

| Import (was `@/…`) | Move to | Symbols |
|---|---|---|
| `@/types` | `@cipherstash/stack/types` | `BulkEncryptedData`, `ClientConfig`, `Encrypted`, `QueryTypeName`, `queryTypes` |
| `@/errors` | `@cipherstash/stack/errors` | (errors) |
| `@/identity` | `@cipherstash/stack/identity` | `LockContext` |
| `@/schema` | `@cipherstash/stack/schema` | `EncryptedColumn`, `EncryptedTable`, … |
| `@/eql/v3` | `@cipherstash/stack/eql/v3` | v3 table/column API, `AnyEncryptedV3Column` |
| `@/encryption`, `@/encryption/index.js` | `@cipherstash/stack` | `Encryption`, `EncryptionClient` |
| `@/utils/logger` | `@cipherstash/stack/adapter-kit` | `logger` |
| `@/encryption/helpers` | `@cipherstash/stack/adapter-kit` | `bulkModelsToEncryptedPgComposites`, `modelToEncryptedPgComposites` |
| `@/encryption/operations/base-operation` | `@cipherstash/stack/adapter-kit` | `AuditConfig` |
| `@/eql/v3/columns` | `@cipherstash/stack/adapter-kit` | `EncryptedV3Column`, `DATE_LIKE_CASTS` (+ `AnyEncryptedV3Column` via `./eql/v3`) |
| `@/eql/v3/domain-registry` | `@cipherstash/stack/adapter-kit` | `DOMAIN_REGISTRY`, `factoryForDomain`, `stripDomainSchema` |
| `@/schema/match-defaults` | `@cipherstash/stack/adapter-kit` | `matchNeedleError` |

The adapters are **leaf modules** — nothing in `packages/stack/src` outside the
adapter dirs imports them — so removing them does not break core.

## File inventory to move

- **stack-supabase:** `packages/stack/src/supabase/*` (8 files: `helpers`,
  `index`, `introspect`, `query-builder`, `query-builder-v3`, `schema-builder`,
  `types`, `verify`). Unit tests: the `supabase*` files under
  `packages/stack/__tests__/` (~13). Integration: `packages/stack/integration/supabase/`.
- **stack-drizzle:** `packages/stack/src/drizzle/*` (v2) **and**
  `packages/stack/src/eql/v3/drizzle/*`. Unit tests: `drizzle*` under
  `packages/stack/__tests__/` + `__tests__/drizzle-v3/`. Integration:
  `packages/stack/integration/drizzle-v3/`.

## Phased steps (per package; do Supabase first as the proven slice)

1. Scaffold the package (`package.json` with `@cipherstash/stack: workspace:*` +
   `@cipherstash/protect-ffi` at stack's pinned version, `pg`/`@types/pg` if
   introspection needs them; `tsconfig.json`, `tsup.config.ts`, `vitest.config.ts`
   — copy prisma-next's shape). Export `.` (the adapter entry).
2. `git mv` the src dir(s) into the package.
3. Rewrite imports per the table above (`@/…` → `@cipherstash/stack[/subpath]`).
   Relative imports within the moved tree stay as-is.
4. Remove the adapter's subpath from stack: `exports`, `typesVersions`,
   `tsup.config.ts` entry. (`./supabase`, `./drizzle`, `./eql/v3/drizzle`.)
5. Build stack, then the new package (src only). Get green before touching tests.
6. Move the unit + integration test files; rewrite their imports (watch for tests
   that reach stack `__tests__/helpers/**` — those helpers may need to move to
   `@cipherstash/test-kit` or be duplicated). Wire the package's vitest config +
   integration config against `@cipherstash/test-kit`.
7. Update the `fta-v3.yml` complexity gate: its `analyze:complexity` scans
   `packages/stack/src/eql/v3`; update the path filter and add an equivalent gate
   in stack-drizzle so the moved code keeps its budget.
8. Update doc/skill references (~13 for `@cipherstash/stack/drizzle`, plus the
   Supabase reference docs and `skills/stash-supabase` / `skills/stash-drizzle`) —
   these ship in the `stash` tarball.
9. Changesets: breaking (removed subpaths from stack) + new-package changesets.

## Verification checklist

- `pnpm --filter @cipherstash/stack build` + `test:types` green (core still builds
  with the subpaths removed).
- `pnpm --filter @cipherstash/stack-supabase build && … test` green; same for
  stack-drizzle.
- `pnpm -w build` green (no dependency cycle: stack must not import the adapters).
- `pnpm install --frozen-lockfile` clean.
- The two integration workflows point at the moved suites.
- `stash manifest --json` unaffected (CLI surface unchanged by this refactor).

## Open questions for review

1. Approve the `adapter-kit` expose approach, or prefer relocation for specific
   symbols (esp. `logger` → `@cipherstash/utils`)?
2. Package names: `@cipherstash/stack-supabase` / `@cipherstash/stack-drizzle`
   (matches the plan) — confirm.
3. Version/`publishConfig`: start both at `0.1.0`, `access: public`?
4. Test-helper coupling: move shared `__tests__/helpers/**` into
   `@cipherstash/test-kit`, or duplicate the few the adapters need?
