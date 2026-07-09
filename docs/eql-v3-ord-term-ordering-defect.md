# EQL v3 non-superuser limitation: `ORDER BY eql_v3.ord_term(col)` does not sort in ORE order

**Status:** Root-caused with live evidence. This is **not** a bug in our SDK and
not a defect in the EQL bundle — it is a **known platform limitation** of the
current (ORE-based) vendored EQL v3 bundle on non-superuser Postgres
(e.g. Supabase). The superuser gate on the ORE operator class is an intentional
install constraint so the bundle installs at all on managed Postgres, where an
ORE ordered index genuinely cannot exist. Our tests/docs are corrected to stop
relying on the construct that is silently wrong in that state; the resolution
(an upstream `_ord`→OPE migration) is tracked as a follow-up (see
[Resolution](#resolution)).

## Summary

For an encrypted ordering column (any `*_ord` / `text_search` domain), the range
comparison functions `eql_v3.gte`/`lte`/`lt`/`gt` sort **correctly** (true ORE
order), but on a non-superuser install `ORDER BY eql_v3.ord_term(col)` sorts
**incorrectly** — deterministic but not the ORE/lexical order.

Reproduced against live Postgres (role `is_superuser = off`) with emails
`ada@example.com`, `grace@example.com`, `alan@example.net`, `zora@example.org`:

| Construct | Result | Correct? |
|---|---|---|
| pairwise `eql_v3.lt(col, col)` (the ORE comparator) | `ada < alan < grace < zora` | ✅ ORE/lexical |
| `ORDER BY eql_v3.ord_term(col)` | `zora, alan, ada, grace` | ❌ record_ops |
| `ORDER BY col` (domain default) | `grace, ada, alan, zora` (structural) | ❌ jsonb_ops |
| `ORDER BY col USING <` / `USING OPERATOR(public.<)` | error: *operator < is not a valid ordering operator* | ❌ no orderable family |

So on a non-superuser install there is **no** `ORDER BY` construct that yields
ORE order. Only the boolean comparison operators (used in `WHERE` predicates) are
ORE-correct — and they are correct regardless of superuser.

## Why this happens on Supabase

File: `packages/stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql`
(the vendored bundle — do not hand-edit; it is regenerated on re-vendor).

1. `eql_v3.ord_term(a public.text_search)` (and every `*_ord` domain, e.g.
   `public.integer_ord` at line 18117) returns the **composite** type
   `eql_v3_internal.ore_block_256` — line **38141-38144**:
   ```sql
   CREATE FUNCTION eql_v3.ord_term(a public.text_search)
   RETURNS eql_v3_internal.ore_block_256 ...
   ```
   `ore_block_256` is `CREATE TYPE ... AS (terms eql_v3_internal.ore_block_256_term[])`
   at line **193**.

2. The ORE-correct default btree opclass for that composite type,
   `eql_v3_internal.ore_block_256_operator_class` (backed by
   `eql_v3_internal.compare_ore_block_256_terms`), is created inside a
   superuser-gated `DO` block — lines **3117-3138**. Creating an operator
   class requires superuser, so on managed/non-superuser Postgres it is
   **intentionally skipped** on `insufficient_privilege` (lines 3134-3136):
   ```
   EQL: skipped operator class eql_v3_internal.ore_block_256_operator_class
   (requires superuser); ORE ordered indexes on ore_block_256 unavailable ...
   ```
   This gate is deliberate: it is what lets the EQL v3 bundle install cleanly on
   Supabase and other non-superuser platforms, where an ORE ordered index cannot
   exist at all. Live check confirms:
   `SELECT ... FROM pg_opclass ... WHERE typname='ore_block_256'` returns `[]`.

3. With the opclass absent, `ORDER BY eql_v3.ord_term(col)` still "works"
   because PostgreSQL supplies a built-in **record comparison** for any
   composite type. That compares the `ore_block_256_term[]` fields by their raw
   bytes — deterministic, but unrelated to ORE order. This is the silent-wrong
   footgun: it does not error, it just sorts wrong.

4. Meanwhile `eql_v3.gte/lte/lt/gt` are ORE-correct **regardless of superuser**
   because they do not go through index/sort machinery. `eql_v3.lt(text_search)`
   (line 38206) is `SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b)`, and the
   `public.<` operator on `ore_block_256` is wired directly to
   `eql_v3_internal.compare_ore_block_256_terms`. The domain-level `<` operator
   (`CREATE OPERATOR <`, line 38566, `FUNCTION = eql_v3.lt`) exists, but it is
   **not** a member of any btree operator family, so `ORDER BY col USING <`
   raises "operator < is not a valid ordering operator".

The bundle comment (lines 3104-3114) documents the missing opclass as the
accepted managed-Postgres limitation ("ORE ordered scans ... unavailable"). The
practical consequence to be aware of is that `ORDER BY ord_term(col)` **silently
returns wrong results** in that state instead of failing, and there is no
non-superuser ORE ordering path on the current bundle.

## Minimal repro

```sql
-- role without superuser; EQL v3 bundle installed
CREATE TABLE t (email public.text_search NOT NULL, label text);
-- insert encrypted 'ada@example.com','grace@example.com',
--                  'alan@example.net','zora@example.org' (labels ada/grace/alan/zora)

SELECT current_setting('is_superuser');                     -- off
SELECT count(*) FROM pg_opclass c JOIN pg_type ty
  ON ty.oid=c.opcintype WHERE ty.typname='ore_block_256';   -- 0

SELECT label FROM t ORDER BY eql_v3.ord_term(email);        -- zora,alan,ada,grace  (WRONG)
-- vs the ORE comparator, which is correct:
SELECT x.label, y.label, eql_v3.lt(x.email, y.email) FROM t x CROSS JOIN t y; -- ada<alan<grace<zora
```

## Resolution

The fix is an upstream change in `cipherstash/encrypt-query-language`, already in
progress, that migrates ordering types off superuser-only ORE:

- All `_ord` types move to **OPE** (Order-Preserving Encryption). OPE orders via
  a **native `bytea` btree**, so `ORDER BY` works **everywhere — including
  Supabase — without superuser**.
- `_ord_ore` types remain **ORE** and are installed **only when superuser is
  available**. On non-superuser installs the ORE types are **not installed at
  all**, so there is no silent-wrong `ORDER BY` path to fall into.
- Net future ordering story: OPE `_ord` orders everywhere; ORE `_ord_ore` is
  superuser-only (and absent on Supabase).

This is a **follow-up** to the current protect-ffi 0.28 PR — it lands as a
separate design spec plus the re-vendored OPE bundle, not as part of this change.

## What we changed in this repo

- `packages/stack/__tests__/schema-v3-pg.test.ts`: corrected the misleading
  comment on the range test and added an explicit ORE-total-order proof using
  pairwise `eql_v3.lt` (the only ORE-correct path on the current bundle), so the
  guarantee is asserted positively rather than merely avoided. These assertions
  go through the comparison operators (`eql_v3.lt`/`gte`/`lte`), which are
  correct regardless of superuser.
- No change to the vendored `.sql` (it is regenerated on re-vendor).
- Docs that prescribe `orderBy: (col) => eql_v3.ord_term(col)` for a future v3
  Drizzle/Prisma adapter (e.g.
  `docs/superpowers/2026-06-12-eql-v3-drizzle-adapter-walkthrough.md`,
  `docs/superpowers/plans/2026-07-06-eql-v3-drizzle-concrete-types.md`) would hit
  this limitation on the current ORE bundle if implemented as written. Any v3
  `orderBy` must not lower to a bare `ORDER BY ord_term(...)` on the current ORE
  bundle; once the OPE `_ord` migration lands, `ORDER BY` on `_ord` becomes
  correct everywhere.
