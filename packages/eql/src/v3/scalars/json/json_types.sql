-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/json/json_types.sql
--! @brief Encrypted-domain types for json.

DO $$
BEGIN
  --! @brief Encrypted domain public.{{prefix}}_json.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_json' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_json AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        -- `"v": null` makes the comparison NULL, and a CHECK that is NULL
        -- passes, so COALESCE refuses it. A NULL value still passes.
        AND COALESCE(VALUE->>'v' = '{{eql_version}}', VALUE IS NULL)
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_json IS 'EQL encrypted json (storage only)';
END
$$;
