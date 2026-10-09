-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/double/double_types.sql
--! @brief Encrypted-domain types for double.

DO $$
BEGIN
  --! @brief Encrypted domain public.{{prefix}}_double.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_double' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_double AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_double IS 'EQL encrypted double (storage only)';

  --! @brief Encrypted domain public.{{prefix}}_double_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_double_eq' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_double_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_double_eq IS 'EQL encrypted double (equality)';

  --! @brief Encrypted domain public.{{prefix}}_double_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_double_ord_ore' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_double_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_double_ord_ore IS 'EQL encrypted double (equality, ordering)';

  --! @brief Encrypted domain public.{{prefix}}_double_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_double_ord' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_double_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_double_ord IS 'EQL encrypted double (equality, ordering)';

  --! @brief Encrypted domain public.{{prefix}}_double_ord_ope.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_double_ord_ope' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_double_ord_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_double_ord_ope IS 'EQL encrypted double (equality, ordering)';
END
$$;
