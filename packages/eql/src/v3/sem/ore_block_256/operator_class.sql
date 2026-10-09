-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/ore_block_256/types.sql
-- REQUIRE: src/v3/sem/ore_block_256/functions.sql
-- REQUIRE: src/v3/sem/ore_block_256/operators.sql

--! @file v3/sem/ore_block_256/operator_class.sql
--! @brief B-tree operator family + default class on {{prefix}}_internal.ore_block_256.
--!
--! Gives the composite type its DEFAULT btree opclass so the recommended
--! functional index `CREATE INDEX ON t ({{prefix}}.ord_term_ore(col))` engages without
--! an explicit opclass annotation (design D4).
--!
--! @note Creating an operator family/class requires superuser: Postgres forbids
--!       CREATE OPERATOR FAMILY / CLASS to non-superusers to protect index
--!       integrity. Managed platforms (Supabase, and most hosted Postgres) run
--!       the installer as a non-superuser role, so the DO block below ATTEMPTS
--!       the creation and skips it on insufficient_privilege (SQLSTATE 42501),
--!       letting the single installer run everywhere. When the class is absent,
--!       ORE ordered scans over {{prefix}}_internal.ore_block_256 are unavailable,
--!       but the order-preserving (OPE) ordering domains — whose extractor
--!       return types carry a native btree opclass — still index without it. On
--!       superuser installs (self-managed Postgres, the SQLx test matrix) the
--!       class is created normally. Any non-privilege error still propagates.
--! @see {{prefix}}_internal.compare_ore_block_256_terms

DO $do$
BEGIN
  EXECUTE 'CREATE OPERATOR FAMILY {{prefix}}_internal.ore_block_256_operator_family USING btree';

  EXECUTE $ddl$
    CREATE OPERATOR CLASS {{prefix}}_internal.ore_block_256_operator_class
      DEFAULT FOR TYPE {{prefix}}_internal.ore_block_256
      USING btree FAMILY {{prefix}}_internal.ore_block_256_operator_family AS
        OPERATOR 1 public.<,
        OPERATOR 2 public.<=,
        OPERATOR 3 public.=,
        OPERATOR 4 public.>=,
        OPERATOR 5 public.>,
        FUNCTION 1 {{prefix}}_internal.compare_ore_block_256_terms(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
  $ddl$;

  RAISE NOTICE 'EQL: created btree operator class {{prefix}}_internal.ore_block_256_operator_class';
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'EQL: skipped operator class {{prefix}}_internal.ore_block_256_operator_class (requires superuser); ORE ordered indexes on ore_block_256 unavailable, OPE ordering domains unaffected';
END;
$do$;
