-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/json/json_types.sql
--! @brief Encrypted-domain types for json.

DO $$
BEGIN
  --! @brief Encrypted domain public.eql_v3_json.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_json' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_json AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_json IS 'EQL encrypted json (storage only)';
END
$$;
