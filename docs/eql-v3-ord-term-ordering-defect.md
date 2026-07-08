# EQL v3 defect: `ORDER BY eql_v3.ord_term(col)` does not sort in ORE order

**Status:** Root-caused with live evidence. The fix does **not** belong in our
SDK — it is an upstream limitation of the vendored EQL v3 bundle. Our tests/docs
are corrected to stop relying on the broken construct; the bundle issue is
recorded here for upstream (`cipherstash/encrypt-query-language`).

## Summary

For an encrypted ordering column (any `*_ord` / `text_search` domain), the range
comparison functions `eql_v3.gte`/`lte`/`lt`/`gt` sort **correctly** (true ORE
order), but `ORDER BY eql_v3.ord_term(col)` sorts **incorrectly** — deterministic
but not the ORE/lexical order.

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
ORE-correct.

## Root cause

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
   **skipped** on `insufficient_privilege` (lines 3134-3136):
   ```
   EQL: skipped operator class eql_v3_internal.ore_block_256_operator_class
   (requires superuser); ORE ordered indexes on ore_block_256 unavailable ...
   ```
   Live check confirms: `SELECT ... FROM pg_opclass ... WHERE typname='ore_block_256'`
   returns `[]`.

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

The bundle comment (lines 3104-3114) treats the missing opclass as an accepted
managed-Postgres limitation ("ORE ordered scans ... unavailable"). The real
defect is that `ORDER BY ord_term(col)` **silently returns wrong results** in
that state instead of failing, and there is no non-superuser ordering path.

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

## Recommended upstream fix (encrypt-query-language)

Provide a non-superuser ordering path so `ORDER BY` is correct everywhere, e.g.
either:
- expose an `eql_v3.order_by(col)` returning a scalar with a **native** btree
  opclass (as EQL v2 does — `eql_v2.order_by()`), or
- make `ord_term`'s return type orderable without a custom opclass, or
- at minimum, make the composite `ore_block_256` have **no** usable default
  comparison so `ORDER BY ord_term(col)` errors loudly instead of sorting wrong.

## What we changed in this repo

- `packages/stack/__tests__/schema-v3-pg.test.ts`: corrected the misleading
  comment on the range test and added an explicit ORE-total-order proof using
  pairwise `eql_v3.lt` (the only ORE-correct path), so the guarantee is asserted
  positively rather than merely avoided.
- No change to the vendored `.sql` (it is regenerated on re-vendor).
- Docs that prescribe `orderBy: (col) => eql_v3.ord_term(col)` for a future v3
  Drizzle/Prisma adapter (e.g.
  `docs/superpowers/2026-06-12-eql-v3-drizzle-adapter-walkthrough.md`,
  `docs/superpowers/plans/2026-07-06-eql-v3-drizzle-concrete-types.md`) would
  ship this defect if implemented as written. Any v3 `orderBy` must not lower to
  a bare `ORDER BY ord_term(...)` until the upstream fix lands.
