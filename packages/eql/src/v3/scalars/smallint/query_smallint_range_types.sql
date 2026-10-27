-- AUTOMATICALLY GENERATED FILE.
-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/ore_fallback.sql

--! @file v3/scalars/smallint/query_smallint_range_types.sql
--! @brief Range query-operand domains for smallint: the operand of `{{prefix}}.between`.
--! @note A range holds both bounds of one `BETWEEN` as one value:
--!       `{"v": {{eql_version}}, "i": {...}, "lo": <term>, "hi": <term>}`. Each bound is the
--!       single-bound query domain's `ob` (ORE) or `op` (OPE) value, in a
--!       `{v, i, lo, hi}` envelope. Both bounds are included. There is one
--!       range domain per ordering term the family stores (ADR-0009,
--!       decisions 7 and 8).
--! @note Cast the range parameter to its exact range domain
--!       (`$1::{{prefix}}.query_smallint_range_ore`). An uncast `$1`, a `jsonb`
--!       parameter, or a range of another term or family fails with 42725
--!       ("function ... is not unique"); see `{{prefix}}.between`.
--! @note EQL version {{eql_version}} only: the `-- ONLY EQL VERSION:` line above keeps this
--!       file out of every other version's installer.
--! @note Like every query operand, a range lives in `{{prefix}}`, not `public`,
--!       and holds no ciphertext `c`. A range whose low bound is above its
--!       high bound matches no row, as with SQL `BETWEEN`; the SQL does not
--!       reorder the bounds.
--! @note On an install without the ORE operator class (a non-superuser
--!       install, on Supabase for instance), the ORE range domain is disabled
--!       as the single-bound ORE domains are: a value cast to it raises
--!       `feature_not_supported`, naming the OPE range. See
--!       `v3/scalars/ore_fallback.sql`.

DO $$
BEGIN
  --! @brief Range query-operand domain {{prefix}}.query_smallint_range_ore (two block ORE bounds; no `c`).
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_smallint_range_ore' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_smallint_range_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'lo'
        AND VALUE ? 'hi'
        AND NOT (VALUE ? 'c')
        AND jsonb_typeof(VALUE -> 'lo') = 'string'
        AND left(VALUE ->> 'lo', 4) IN ('0202', '0203')
        AND jsonb_typeof(VALUE -> 'hi') = 'string'
        AND left(VALUE ->> 'hi', 4) IN ('0202', '0203')
        -- `"v": null` makes the comparison NULL, and a CHECK that is NULL
        -- passes, so COALESCE refuses it. A NULL range still passes (no row
        -- matches it). The comparison keeps the one form the v4 isolation
        -- gate accepts.
        AND COALESCE(VALUE->>'v' = '{{eql_version}}', VALUE IS NULL)
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_smallint_range_ore IS 'EQL smallint range query operand (block ORE)';

  --! @brief Range query-operand domain {{prefix}}.query_smallint_range_ope (two CLLW OPE bounds; no `c`).
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_smallint_range_ope' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_smallint_range_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'lo'
        AND VALUE ? 'hi'
        AND NOT (VALUE ? 'c')
        AND jsonb_typeof(VALUE -> 'lo') = 'string'
        AND left(VALUE ->> 'lo', 2) IN ('00', '01')
        AND jsonb_typeof(VALUE -> 'hi') = 'string'
        AND left(VALUE ->> 'hi', 2) IN ('00', '01')
        -- `"v": null` makes the comparison NULL, and a CHECK that is NULL
        -- passes, so COALESCE refuses it. A NULL range still passes (no row
        -- matches it). The comparison keeps the one form the v4 isolation
        -- gate accepts.
        AND COALESCE(VALUE->>'v' = '{{eql_version}}', VALUE IS NULL)
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_smallint_range_ope IS 'EQL smallint range query operand (CLLW OPE)';
END
$$;

-- Without the default btree operator class on {{prefix}}_internal.{{ore_block}}
-- (the installer skips it on insufficient_privilege), ore_fallback.sql has
-- created {{prefix}}_internal.ore_domain_unavailable and poisoned the
-- single-bound ORE domains. It cannot reach this ORE range, which exists in
-- EQL v4 only, so the same NOT VALID poison CHECK is added here.
DO $do$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_opclass c
    JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
    WHERE am.amname = 'btree'
      AND c.opcdefault
      AND c.opcintype = '{{prefix}}_internal.{{ore_block}}'::pg_catalog.regtype
  ) THEN
    RETURN;
  END IF;

  ALTER DOMAIN {{prefix}}.query_smallint_range_ore ADD CONSTRAINT eql_ore_unavailable
    CHECK ({{prefix}}_internal.ore_domain_unavailable(VALUE, '{{prefix}}.query_smallint_range_ore', '{{prefix}}.query_smallint_range_ope (range)')) NOT VALID;
END;
$do$;
