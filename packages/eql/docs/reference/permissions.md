# EQL permissions & grants

## Design decision: EQL never grants permissions automatically

The EQL installer (`release/cipherstash-encrypt.sql`) issues **no `GRANT` or
`REVOKE` statements**. Access to the `eql_v3` and `eql_v3_internal` schemas — and
to the domains, functions, operators, and aggregates within them — is **strictly
opt-in**. This is a deliberate least-privilege stance, not an oversight.

Two consequences follow from standard PostgreSQL behaviour:

- PostgreSQL does **not** grant `USAGE` on a newly-created schema to `PUBLIC`
  (unlike the special-cased `public` schema). So immediately after install, only
  the **installing role (the owner)** and superusers can use `eql_v3` /
  `eql_v3_internal`.
- Functions are created with the usual default `EXECUTE` to `PUBLIC`, but that is
  moot without `USAGE` on the containing schema.

A deployment that exposes EQL to non-owner roles must grant access explicitly.

## Install privileges

Installing EQL v3 requires only `CREATE` on the target database and schemas —
**no superuser** — with one exception: the block-ORE btree operator
class/family (`eql_v3_internal.ore_block_256_operator_class`). `CREATE
OPERATOR CLASS` / `CREATE OPERATOR FAMILY` are superuser-gated commands in
stock PostgreSQL (every supported version — the [`CREATE OPERATOR
CLASS`](https://www.postgresql.org/docs/current/sql-createopclass.html) page:
"Presently, the creating user must be a superuser"), and the privilege is not
grantable.

The installer handles this gracefully: the opclass is created inside a `DO`
block that catches `insufficient_privilege` (SQLSTATE 42501) and skips with a
`NOTICE`, after which the ORE-backed domains (`_ord_ore`, `text_search_ore`,
and their `eql_v3.query_*` twins) are **disabled** — using one raises
`feature_not_supported` with a `HINT` naming the alternatives (see
[U-003](../upgrading/v3.0.md#u-003-non-superuser-installs-disable-the-ore-backed-domains)).
Everything else — the domains, operators, extractors, aggregates, and every
functional-index recipe except the ORE one — installs and works without
superuser.

Whether a managed platform allows the opclass is **per-platform**, decided by
whether its admin role passes (or the vendor's engine delegates) that
superuser check:

| Platform | ORE opclass installable? | Source |
| --- | --- | --- |
| Self-hosted / containerised PostgreSQL (superuser) | ✅ | stock behaviour |
| Aurora PostgreSQL (13+, and 12.12.0+) | ✅ — delegated to `rds_superuser` | [Aurora release notes 12.12.0](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraPostgreSQLReleaseNotes/AuroraPostgreSQL.Updates.html): "Added support for the rds_superuser role to execute CREATE OPERATOR CLASS…" |
| RDS for PostgreSQL (non-Aurora) | ✅ — the master user can | verified in production CipherStash deployments running ORE with the custom operator class on RDS (AWS does not release-note the delegation the way it does for Aurora — confirm on your instance with the probe below if in doubt) |
| Cloud-hosted Supabase | ❌ — the `postgres` role cannot | [supabase/supautils#72](https://github.com/supabase/supautils/issues/72) (open feature request; "must be superuser to create an operator family") |
| Google Cloud SQL | ❌ | ["Unsupported features"](https://cloud.google.com/sql/docs/postgres/features): "Any feature that requires SUPERUSER" (opclasses are not among the exceptions) |
| Azure Database for PostgreSQL Flexible Server | ❌ (admin is `NOSUPERUSER`; no documented carve-out) | [Azure security docs](https://learn.microsoft.com/en-us/azure/postgresql/security/security-access-control) |

To check any role/platform directly:

```sql
DO $$ BEGIN
  CREATE OPERATOR FAMILY _priv_probe USING btree;
  DROP OPERATOR FAMILY _priv_probe USING btree;
  RAISE NOTICE 'this role can create operator classes/families';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'this role cannot create operator classes/families (SQLSTATE 42501)';
END $$;
```

> **This is a different mechanism from the extension restriction.** Custom
> *extensions* are impossible on managed platforms because `CREATE EXTENSION`
> needs the extension's files on a filesystem customers cannot touch — vendors
> ship a vetted set and may restrict it further (e.g. RDS's
> `rds.allowed_extensions`). The EQL opclass ships **no files**: it is pure
> catalog DDL whose support functions ride on pgcrypto (on every platform's
> supported/trusted list). Only the superuser gate above decides it —
> extension allow-lists are never the reason.

If a database was **installed with the opclass and later loses it** (or an
`_ord_ore` column otherwise exists without it), note that `CREATE INDEX …
btree (eql_v3.ord_term_ore(col))` still succeeds by silently binding
`record_ops` — an index that never engages. See [the detection
query](./database-indexes.md#range-queries-and-order-by) in the indexes guide.

## Granting access (the opt-in step)

For an application role (for example a Supabase `authenticated` / `anon` role, or
a dedicated app role) that queries encrypted columns:

```sql
-- The public API surface: domains, operators, function equivalents, aggregates.
GRANT USAGE ON SCHEMA eql_v3 TO app_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3 TO app_role;

-- The internal surface. The supported operators and aggregates dispatch into it
-- (see "What each query path requires" below), so a role that runs equality or
-- ordering queries, aggregates, or writes encrypted JSON needs it too.
GRANT USAGE ON SCHEMA eql_v3_internal TO app_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3_internal TO app_role;

-- pgcrypto (Supabase installs it here). The ORE comparison behind ordering and
-- MIN/MAX calls pgcrypto `encrypt()`, so ordered/aggregated queries need USAGE
-- on its schema. (The installer accepts pgcrypto only in `extensions` or in
-- `public`; `public` needs no grant.)
GRANT USAGE ON SCHEMA extensions TO app_role;

-- Optionally keep future functions granted:
ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v3 GRANT EXECUTE ON FUNCTIONS TO app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v3_internal GRANT EXECUTE ON FUNCTIONS TO app_role;
```

Grant only what the deployment needs; the mapping below lets you narrow further.

### What each query path requires

`eql_v3_internal` is **not** a public API — you never name its objects directly —
but the supported `eql_v3` surface *reaches into it*, so a query role commonly
needs `USAGE` on it anyway. The exact requirement is path-dependent:

| Query path | `eql_v3` | `eql_v3_internal` | `extensions` (pgcrypto) |
| --- | :---: | :---: | :---: |
| Equality (`=` / `eql_v3.eq`) | ✅ | ✅ | — |
| Ordering (`<` `<=` `>` `>=` / `eql_v3.lt`…) | ✅ | ✅ | only on `_ord_ore` / `text_search_ore` |
| `MIN` / `MAX` aggregates | ✅ | ✅ | only on `_ord_ore` / `text_search_ore` |
| jsonb containment read (`@>` `<@` / `jsonb_document_contains`) | ✅ | — | — |
| Cast/write raw JSON → `public.eql_v3_json_search` or a scalar domain (`public.eql_v3_integer`…) | — | — | — |
| Cast a query operand → `eql_v3.query_<name>` / `eql_v3.query_json` | ✅ | — | — |

Why the internal grant is needed even though you only call public objects:

- **Equality** inlines the index-term constructor
  `eql_v3_internal.hmac_256(jsonb)` (via `eq_term`); **ordering** inlines
  `eql_v3_internal.ope_cllw` (via `ord_term`) on the `_ord` / `_ord_ope` /
  `text_search`
  domains, or `eql_v3_internal.ore_block_256` (via `ord_term_ore`) and its comparator
  on `_ord_ore` / `text_search_ore`. The public
  wrappers are inlinable SQL, so the internal call becomes part of *your* query
  and is checked against *your* role's privileges.
- **`MIN`/`MAX`** dispatch into the aggregate state functions
  `eql_v3_internal.min_sfunc` / `max_sfunc`.
- The **ORE comparison** behind ordering and `MIN`/`MAX` on the block-ORE
  variants (`_ord_ore`, `text_search_ore`) calls pgcrypto `encrypt()`, which the
  installer places in the `extensions` schema — hence the `USAGE` there. The
  CLLW-OPE variants (`_ord`, `_ord_ope`, `text_search`) compare native `bytea`
  and need no `extensions` grant.
- **Casting raw jsonb to `public.eql_v3_json_search`** fires a domain `CHECK`
  that calls the `public.eql_v3_is_valid_ste_vec_*` validators — deliberately
  kept in `public` so application table columns survive an EQL schema
  uninstall — so it needs **no** schema grant at all. (Scalar domain CHECKs —
  and, since issue #354, the `public.eql_v3_json_entry` CHECK — are pure
  structural jsonb tests, likewise grant-free. Casting to the
  `eql_v3.query_*` operand domains needs `USAGE` on `eql_v3` only because the
  domains themselves live there.)

The hand-written jsonb containment **read** path (`eql_v3.jsonb_document_contains` and
the `@>` / `<@` operators over it) stays within `eql_v3` / `public` — the array
variant is `plpgsql` (never inlined) and the typed variant inlines only `eql_v3`
calls — so it runs under the public `eql_v3` grant alone.

This behaviour is gated by `tests/sqlx/tests/v3_privilege_tests.rs`. So the
public **function equivalents** (below) change *how* you invoke a supported
operation on operator-free platforms — not *which* schemas you must grant.

## Operators vs. function equivalents (operator-free platforms)

Not every platform can invoke custom operators. Supabase/PostgREST, for example,
exposes the database through an auto-generated REST/RPC layer that calls
**functions**, not operators — `WHERE col = $1` is not expressible over that
interface, but `eql_v3.eq(col, $1)` is.

For this reason **every supported EQL operator has a public function equivalent
in `eql_v3`**:

| Operator | Public function equivalent |
| --- | --- |
| `=` | `eql_v3.eq(a, b)` |
| `<>` | `eql_v3.neq(a, b)` |
| `<` `<=` `>` `>=` | `eql_v3.lt` / `lte` / `gt` / `gte(a, b)` |
| `@@` (text match) | `eql_v3.matches(a, b)` |
| `@>` `<@` (jsonb documents) | `eql_v3.jsonb_contains` / `jsonb_contained_by(a, b)`, and the typed `eql_v3.jsonb_document_contains` |
| `MIN` / `MAX` | `eql_v3.min` / `eql_v3.max` aggregates |

This invariant is enforced by
`tests/sqlx/tests/v3_operator_equivalents_tests.rs`: any supported operator whose
backing wrapper is hidden in `eql_v3_internal` fails CI.
