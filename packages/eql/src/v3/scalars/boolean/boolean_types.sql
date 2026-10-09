-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/boolean/boolean_types.sql
--! @brief Encrypted-domain types for boolean.

DO $$
BEGIN
  --! @brief Encrypted domain public.{{prefix}}_boolean.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_boolean' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_boolean AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_boolean IS 'EQL encrypted boolean (storage only)';
END
$$;
