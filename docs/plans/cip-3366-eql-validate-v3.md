# CIP-3366 — Rewrite `eql validate` for the EQL v3 domain-type vocabulary

## Step 0 — Branch & worktree

```bash
git worktree add .claude/worktrees/toby+cip-3366-eql-validate-v3 \
  -b toby/cip-3366-rewrite-eql-validate-for-the-eql-v3-domain-type-vocabulary
cd .claude/worktrees/toby+cip-3366-eql-validate-v3
pnpm install
pnpm --filter @cipherstash/stack build   # cli resolves stack through dist/
```

## Two decisions that shape everything else

### 1. `EncryptConfig` is lossy — validate must read domains, not indexes

`EncryptedV3Column.build()` emits only `{ cast_as, indexes }`; the comment on
`getEqlType()` says outright "Metadata only; not emitted by `build()`". So
`cast_as: 'number'` + `{ ope: {} }` is ambiguous across `eql_v3_integer_ord`,
`smallint_ord`, `real_ord`, `double_ord` and `numeric_ord`. Every new rule in the
issue — `_ord_ore` steering, bool-not-searchable, text-only match, declared-vs-observed
drift — needs the domain name.

The tables are usually imported into the client file rather than re-exported from
it (see the scaffold's `import { users, orders } from './db/schema'`), so
duck-typing the module namespace is unreliable. Expose them on the client instead.

**`packages/stack/src/encryption/client-v3.ts`**

- Add `getSchemas(): S` to the `EncryptionClient` interface.
- Add `getSchemas: () => schemas` to the `typed` object returned by
  `createEncryptionClient` (`schemas` is already a parameter — ~2 lines).
- Test in `packages/stack/__tests__/`: `getSchemas()` returns the tuple and each
  column's `getEqlType()` round-trips.
- Changeset: `@cipherstash/stack` minor. Update `skills/stash-encryption`.

**`packages/cli/src/config/index.ts`** — add `loadEncryptSchemas(path)` beside
`loadEncryptConfig`, reusing the same jiti load and the same
`requireUsableEncryptConfig` placeholder guard, returning
`{ config, schemas }`. Fall back to config-only with a warning if the client
predates `getSchemas` (older `@cipherstash/stack` in a customer repo).

### 2. Empty-string ordering is not statically checkable — scope it out

The issue lists "Ordered domains reject empty strings (CHECK requires non-empty
`ob`)". That is a value-level CHECK enforced at encrypt time; nothing in the
schema or in `information_schema` predicts it. Leave it out and file a
follow-up to improve the *error message* on that path instead. Say so in the PR.

## Step 1 — Validation core

New: `packages/cli/src/commands/eql/validate.ts`. Keep the pure core separate
from the command shell so it is unit-testable (the current file has no tests at
all).

```ts
interface DeclaredColumn {
  table: string
  column: string        // DB name, from getName()
  eqlType: string       // 'public.eql_v3_integer_ord'
  castAs: PlaintextKind
  queryable: boolean
  indexes: ColumnSchema['indexes']
}

collectDeclaredColumns(schemas): DeclaredColumn[]
validateSchemas(cols, observed?: ObservedState): ValidationIssue[]
```

Keep the existing `ValidationIssue` / `reportIssues` shape and the
error-exits-1 contract.

### Static rules (no database)

| Rule | Severity | Detection |
|---|---|---|
| `_ord_ore` domain declared | Warning | `eqlType.endsWith('_ord_ore')` — the ORE opclass is superuser-only; steer to the `_ord` (OPE) twin, which indexes on managed Postgres |
| Column is not queryable | Info | `!column.isQueryable()` — successor to the v2 "no indexes" Info, now correct for `types.IntegerOrd` (see the bug below) |
| Searchable `bool` | Error | `castAs === 'boolean' && queryable` |
| `match` index on a non-text domain | Error | `indexes.match && castAs !== 'string'` |
| `ste_vec` without a json domain | Error | keep from v2; retarget the message at `types.Json` |

Retired: the operator-family warning, `NON_STRING_CAST_TYPES`, and the
`--exclude-operator-family` flag (`validateInstallFlags` already hard-rejects it
with "v3 self-adapts", and `v2-retirement.test.ts:23` asserts it is gone from
`eql install`/`upgrade` — validate is the last consumer).

The bool and text-only rules are unconstructible through `types.*` today; they
are guards for hand-authored configs and for the drift rules below, not the
value of this step. Note that honestly in the PR.

### Database rules (when a URL resolves)

Skip with a `p.log.info` notice when no URL resolves — do not fail. Reuse
`fetchPhysicalColumns` from `packages/cli/src/commands/encrypt/lib/db-readers.ts`
(already returns `table → column → domain_name`).

| Rule | Severity |
|---|---|
| Declared column absent from the database | Error |
| Observed `domain_name` ≠ declared `eqlType` (minus the `public.` prefix) | Error |
| Observed column has no domain (plain `jsonb`/`text`) | Error |
| `_ord_ore` declared while the ORE opclass is absent | Error (upgrades the static Warning) |
| Queryable column with no functional index over its extractor | Info |

ORE availability probe — mirrors the shipped bundle's own fallback test
(`@cipherstash/eql@3.0.4` `dist/sql/cipherstash-encrypt.sql`, the
`ore_fallback.sql` `DO` block):

```sql
SELECT EXISTS (
  SELECT 1
  FROM pg_catalog.pg_opclass c
  JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
  WHERE am.amname = 'btree'
    AND c.opcdefault
    AND c.opcintype = to_regtype('eql_v3_internal.ore_block_256')
) AS ore_available;
```

`to_regtype` returns NULL instead of throwing when EQL is not installed, so the
probe degrades to `false`. Detect not-installed separately and report that
first, or the user gets "ORE unavailable" when the real answer is "run
`stash eql install`".

Functional-index rule: read `pg_index` + `pg_get_indexdef` and look for
`eql_v3.eq_term` / `eql_v3.ord_term` / `eql_v3.ord_term_ore` /
`eql_v3.match_term` over the column. This is the finding
`skills/stash-indexing` already promises to resolve, so it keeps that skill's
cross-reference honest.

## Step 2 — Command wiring

- `runEqlCommand` (`packages/cli/src/bin/main.ts`): add `case 'validate'`.
- `runDbCommand`: `case 'validate'` warns via `messages.db.aliasDeprecated(STASH, 'validate')`
  and forwards — same shape as `install` / `upgrade` / `status`. (The issue
  assumes this alias already exists; it does not.)
- `packages/cli/src/cli/registry.ts`: move the entry from the Database group to
  the EQL group as `eql validate`; flags `SUPABASE_COMPAT_FLAG` +
  `DATABASE_URL_FLAG` only.
- `main.ts` HELP text (line 117): `db validate` → `eql validate`.
- Delete `packages/cli/src/commands/db/validate.ts`.

## Step 3 — Tests

New `packages/cli/src/commands/eql/__tests__/validate.test.ts`, table-driven over
real `encryptedTable` / `types.*` schemas rather than hand-built configs, with a
fake observed-state map for the DB rules.

Pin the regression this issue exists for:

```ts
// v2 validate reported both of these as "encrypted but has no indexes —
// it will not be searchable": hasAnyIndex never learned about `ope`.
const t = encryptedTable('users', {
  age: types.IntegerOrd('age'),
  createdAt: types.TimestampOrd('created_at'),
})
expect(validateSchemas(collectDeclaredColumns([t]))).toEqual([])
```

Extend `packages/cli/src/__tests__/v2-retirement.test.ts`: `eql validate` carries
no `--exclude-operator-family`, and `db validate` is absent from the registry.

## Step 4 — Docs, skills, changesets

Skills ship in the `stash` tarball, so these are part of the change, not follow-up:

- `skills/stash-cli/SKILL.md:430` — rewrite the rule table, move the section from
  Database to EQL, drop the operator-family row.
- `skills/stash-indexing/SKILL.md:17,272` — rename the "No indexes on an
  encrypted column" finding to whatever Step 1 emits.
- `skills/stash-postgres/SKILL.md:468` — cross-reference.
- `skills/stash-encryption` — the new `getSchemas()` accessor.
- `packages/cli/README.md:69,217,222`.
- Scaffold comments naming `stash db validate`:
  `packages/cli/src/commands/init/utils.ts:388,437,455,500` **and** the checked-in
  fixtures `packages/cli/__fixtures__/scaffold/{generic,drizzle}.generated.ts` —
  `placeholder-client-fixture.test.ts` compares them, so both move together.
- Changesets: `@cipherstash/stack` minor (accessor), `stash` minor (command move,
  new rules, flag removal).

No wizard change needed: `ALLOWED_DLX_TOOLS` / `ALLOWED_BASH_COMMANDS` already
allow the `stash eql` prefix.

## Verification

```bash
pnpm run code:fix
pnpm --filter @cipherstash/stack build && pnpm --filter @cipherstash/stack test
pnpm --filter stash build && pnpm --filter stash test
node packages/cli/dist/bin/stash.js manifest --json   # diff against skills/stash-cli
```

Manual against a live database: one `_ord_ore` column on a non-superuser role
(Error), one drifted domain, one queryable column with no functional index.
