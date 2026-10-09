-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/ore_block_256/operator_class.sql
-- REQUIRE: src/v3/scalars/integer/integer_types.sql
-- REQUIRE: src/v3/scalars/integer/query_integer_types.sql
-- REQUIRE: src/v3/scalars/smallint/smallint_types.sql
-- REQUIRE: src/v3/scalars/smallint/query_smallint_types.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/query_bigint_types.sql
-- REQUIRE: src/v3/scalars/date/date_types.sql
-- REQUIRE: src/v3/scalars/date/query_date_types.sql
-- REQUIRE: src/v3/scalars/timestamp/timestamp_types.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_types.sql
-- REQUIRE: src/v3/scalars/numeric/numeric_types.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_types.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/real/real_types.sql
-- REQUIRE: src/v3/scalars/real/query_real_types.sql
-- REQUIRE: src/v3/scalars/double/double_types.sql
-- REQUIRE: src/v3/scalars/double/query_double_types.sql

--! @file v3/scalars/ore_fallback.sql
--! @brief Disable the ORE-backed encrypted domains when the ORE operator class is absent.
--!
--! Runs after the DO block in src/v3/sem/ore_block_256/operator_class.sql,
--! which ATTEMPTS to create the default btree operator class for
--! {{prefix}}_internal.ore_block_256 and skips it on insufficient_privilege
--! (CREATE OPERATOR CLASS requires superuser; managed platforms — cloud
--! Supabase and most hosted Postgres — run the installer as a non-superuser
--! role). When the class was created, this file is a no-op.
--!
--! When the class was skipped, the ORE-carrying domains would otherwise
--! install half-working: `<`/`>` comparisons still run (as unindexable seq
--! scans), while `CREATE INDEX ... ({{prefix}}.ord_term(col))` and bare
--! `ORDER BY` fail with opaque Postgres errors. Instead of that silent
--! degradation, this file poisons every ORE-carrying domain (and its
--! query-operand twin) with an always-raising CHECK constraint, so the first
--! value coerced into the domain fails loudly and points at the
--! platform-supported alternatives (OPE ordering / HMAC equality /
--! bloom-filter match).
--!
--! Footguns honoured (see the encrypted-domain footgun list in CLAUDE.md):
--! the poison function is LANGUAGE plpgsql (never inlined, so the RAISE
--! cannot be planned away) and NOT STRICT (a STRICT function is skipped for
--! NULL inputs, which would silently let NULLs through the poisoned domain).
--!
--! The poison constraints are added NOT VALID. For domains — unlike table
--! constraints — this does not weaken enforcement: coercion applies every
--! constraint regardless of validation status, so new casts and inserts
--! (including NULL) still raise. What it skips is validating existing stored
--! data: without it, re-running the installer over a database that already
--! holds ORE values (written under an earlier superuser install, before the
--! installing role was demoted) would run the always-raising poison against
--! every stored row and abort the install.

DO $do$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_opclass c
    JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
    WHERE am.amname = 'btree'
      AND c.opcdefault
      AND c.opcintype = '{{prefix}}_internal.ore_block_256'::pg_catalog.regtype
  ) THEN
    RETURN;
  END IF;

  --! @brief Poison CHECK backing for the ORE-carrying domains on platforms
  --!        without the ORE operator class. Always raises; never returns.
  --! @internal
  CREATE FUNCTION {{prefix}}_internal.ore_domain_unavailable(val jsonb, domain_name text, alternatives text)
  RETURNS boolean
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
  LANGUAGE plpgsql
  AS $poison$
  BEGIN
    RAISE EXCEPTION 'EQL: % cannot be used on this platform: the EQL installer could not create the ORE operator class (requires superuser, unavailable on e.g. cloud-hosted Supabase)', domain_name
      USING HINT = 'Use ' || alternatives || ' instead.',
            ERRCODE = 'feature_not_supported';
  END;
  $poison$;
  -- NOT VALID: skip validating existing stored data (rows written under an
  -- earlier superuser install must stay readable, and re-installing over them
  -- must not abort). Domain coercion still enforces the CHECK on every new
  -- cast/insert regardless of validation status.

  ALTER DOMAIN public.{{prefix}}_integer_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_integer_ord_ore', 'public.{{prefix}}_integer_eq (equality) or public.{{prefix}}_integer_ord (ordering) or public.{{prefix}}_integer_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_integer_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_integer_ord_ore', '{{prefix}}.query_integer_eq (equality) or {{prefix}}.query_integer_ord (ordering) or {{prefix}}.query_integer_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_smallint_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_smallint_ord_ore', 'public.{{prefix}}_smallint_eq (equality) or public.{{prefix}}_smallint_ord (ordering) or public.{{prefix}}_smallint_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_smallint_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_smallint_ord_ore', '{{prefix}}.query_smallint_eq (equality) or {{prefix}}.query_smallint_ord (ordering) or {{prefix}}.query_smallint_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_bigint_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_bigint_ord_ore', 'public.{{prefix}}_bigint_eq (equality) or public.{{prefix}}_bigint_ord (ordering) or public.{{prefix}}_bigint_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_bigint_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_bigint_ord_ore', '{{prefix}}.query_bigint_eq (equality) or {{prefix}}.query_bigint_ord (ordering) or {{prefix}}.query_bigint_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_date_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_date_ord_ore', 'public.{{prefix}}_date_eq (equality) or public.{{prefix}}_date_ord (ordering) or public.{{prefix}}_date_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_date_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_date_ord_ore', '{{prefix}}.query_date_eq (equality) or {{prefix}}.query_date_ord (ordering) or {{prefix}}.query_date_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_timestamp_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_timestamp_ord_ore', 'public.{{prefix}}_timestamp_eq (equality) or public.{{prefix}}_timestamp_ord (ordering) or public.{{prefix}}_timestamp_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_timestamp_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_timestamp_ord_ore', '{{prefix}}.query_timestamp_eq (equality) or {{prefix}}.query_timestamp_ord (ordering) or {{prefix}}.query_timestamp_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_numeric_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_numeric_ord_ore', 'public.{{prefix}}_numeric_eq (equality) or public.{{prefix}}_numeric_ord (ordering) or public.{{prefix}}_numeric_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_numeric_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_numeric_ord_ore', '{{prefix}}.query_numeric_eq (equality) or {{prefix}}.query_numeric_ord (ordering) or {{prefix}}.query_numeric_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_text_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_text_ord_ore', 'public.{{prefix}}_text_eq (equality) or public.{{prefix}}_text_match (match) or public.{{prefix}}_text_ord (ordering) or public.{{prefix}}_text_ord_ope (ordering) or public.{{prefix}}_text_search (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_text_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_text_ord_ore', '{{prefix}}.query_text_eq (equality) or {{prefix}}.query_text_match (match) or {{prefix}}.query_text_ord (ordering) or {{prefix}}.query_text_ord_ope (ordering) or {{prefix}}.query_text_search (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_text_search_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_text_search_ore', 'public.{{prefix}}_text_eq (equality) or public.{{prefix}}_text_match (match) or public.{{prefix}}_text_ord (ordering) or public.{{prefix}}_text_ord_ope (ordering) or public.{{prefix}}_text_search (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_text_search_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_text_search_ore', '{{prefix}}.query_text_eq (equality) or {{prefix}}.query_text_match (match) or {{prefix}}.query_text_ord (ordering) or {{prefix}}.query_text_ord_ope (ordering) or {{prefix}}.query_text_search (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_real_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_real_ord_ore', 'public.{{prefix}}_real_eq (equality) or public.{{prefix}}_real_ord (ordering) or public.{{prefix}}_real_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_real_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_real_ord_ore', '{{prefix}}.query_real_eq (equality) or {{prefix}}.query_real_ord (ordering) or {{prefix}}.query_real_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN public.{{prefix}}_double_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, 'public.{{prefix}}_double_ord_ore', 'public.{{prefix}}_double_eq (equality) or public.{{prefix}}_double_ord (ordering) or public.{{prefix}}_double_ord_ope (ordering)')) NOT VALID;

  ALTER DOMAIN {{prefix}}.query_double_ord_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_double_ord_ore', '{{prefix}}.query_double_eq (equality) or {{prefix}}.query_double_ord (ordering) or {{prefix}}.query_double_ord_ope (ordering)')) NOT VALID;

  RAISE NOTICE 'EQL: ORE operator class absent (creation requires superuser) — 20 ORE-backed domains disabled and will raise on use; use the _ord_ope (ordering) and _eq (equality) domains — and text_match for text pattern match — instead';
END;
$do$;
