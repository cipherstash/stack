-- AUTOMATICALLY GENERATED FILE.
-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/integer/query_integer_range_types.sql
--! @brief Range query-operand domains for integer: the operand of `{{prefix}}.between`.
--! @note A range holds both bounds of one `BETWEEN` as one value:
--!       `{"v": {{eql_version}}, "i": {...}, "lo": <term>, "hi": <term>}`. Each bound is the
--!       value the family's single-bound query domain for the same ordering
--!       term holds under its term key (`ob` or `op`). Both bounds are
--!       included. There is one range domain per ordering term the family
--!       stores (ADR-0009, decisions 7 and 8).
--! @note EQL version {{eql_version}} only: the `-- ONLY EQL VERSION:` line above keeps this
--!       file out of every other version's installer.
--! @note Like every query operand, a range lives in `{{prefix}}`, not `public`,
--!       and holds no ciphertext `c`. The client refuses a range whose low
--!       bound is above its high bound; one that reaches the database anyway
--!       matches no row.

DO $$
BEGIN
  --! @brief Range query-operand domain {{prefix}}.query_integer_range_ore (two block ORE bounds; no `c`).
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_integer_range_ore' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_integer_range_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'lo'
        AND VALUE ? 'hi'
        AND NOT (VALUE ? 'c')
        AND jsonb_typeof(VALUE -> 'lo') = 'array'
        AND jsonb_array_length(VALUE -> 'lo') > 0
        AND jsonb_typeof(VALUE -> 'hi') = 'array'
        AND jsonb_array_length(VALUE -> 'hi') > 0
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_integer_range_ore IS 'EQL integer range query operand (block ORE)';

  --! @brief Range query-operand domain {{prefix}}.query_integer_range_ope (two CLLW OPE bounds; no `c`).
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_integer_range_ope' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_integer_range_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'lo'
        AND VALUE ? 'hi'
        AND NOT (VALUE ? 'c')
        AND jsonb_typeof(VALUE -> 'lo') = 'string'
        AND jsonb_typeof(VALUE -> 'hi') = 'string'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_integer_range_ope IS 'EQL integer range query operand (CLLW OPE)';
END
$$;
