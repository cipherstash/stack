-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/numeric/numeric_types.sql
--! @brief Encrypted-domain types for numeric.

DO $$
BEGIN
  --! @brief Encrypted domain public.eql_v3_numeric.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_numeric' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_numeric AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_numeric IS 'EQL encrypted numeric (storage only)';

  --! @brief Encrypted domain public.eql_v3_numeric_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_numeric_eq' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_numeric_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_numeric_eq IS 'EQL encrypted numeric (equality)';

  --! @brief Encrypted domain public.eql_v3_numeric_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_numeric_ord_ore' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_numeric_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_numeric_ord_ore IS 'EQL encrypted numeric (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_numeric_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_numeric_ord' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_numeric_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_numeric_ord IS 'EQL encrypted numeric (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_numeric_ord_ope.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_numeric_ord_ope' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_numeric_ord_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_numeric_ord_ope IS 'EQL encrypted numeric (equality, ordering)';
END
$$;
