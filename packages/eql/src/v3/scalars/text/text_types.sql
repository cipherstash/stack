-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/text/text_types.sql
--! @brief Encrypted-domain types for text.

DO $$
BEGIN
  --! @brief Encrypted domain public.eql_v3_text.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text IS 'EQL encrypted text (storage only)';

  --! @brief Encrypted domain public.eql_v3_text_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_eq' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_eq IS 'EQL encrypted text (equality)';

  --! @brief Encrypted domain public.eql_v3_text_match.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_match' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_match AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'bf'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_match IS 'EQL encrypted text (matching)';

  --! @brief Encrypted domain public.eql_v3_text_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_ord_ore' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_ord_ore IS 'EQL encrypted text (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_text_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_ord' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_ord IS 'EQL encrypted text (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_text_ord_ope.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_ord_ope' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_ord_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'op'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_ord_ope IS 'EQL encrypted text (equality, ordering)';

  --! @brief Encrypted domain public.eql_v3_text_search_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_search_ore' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_search_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'ob'
        AND VALUE ? 'bf'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_search_ore IS 'EQL encrypted text (equality, ordering, matching)';

  --! @brief Encrypted domain public.eql_v3_text_search.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_text_search' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_text_search AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'op'
        AND VALUE ? 'bf'
        AND VALUE->>'v' = '3'
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_text_search IS 'EQL encrypted text (equality, ordering, matching)';
END
$$;
