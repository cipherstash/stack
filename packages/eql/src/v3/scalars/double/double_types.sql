-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/double/double_types.sql
--! @brief Encrypted-domain types for double.

DO $$
BEGIN
  --! @brief Encrypted domain public.eql_v3_double.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_double' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_double AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_double IS 'EQL encrypted double (storage only)';

  --! @brief Encrypted domain public.eql_v3_double_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_double_eq' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_double_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_double_eq IS 'EQL encrypted double (equality)';

  --! @brief Encrypted domain public.eql_v3_double_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_double_ord_ore' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_double_ord_ore AS jsonb
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

  COMMENT ON DOMAIN public.eql_v3_double_ord_ore IS 'EQL encrypted double (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_double_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_double_ord' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_double_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_double_ord IS 'EQL encrypted double (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_double_ord_ope.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_double_ord_ope' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_double_ord_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_double_ord_ope IS 'EQL encrypted double (equality, ordering)';
END
$$;
