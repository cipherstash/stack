-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/smallint/smallint_types.sql
--! @brief Encrypted-domain types for smallint.

DO $$
BEGIN
  --! @brief Encrypted domain public.{{prefix}}_smallint.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_smallint' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_smallint AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_smallint IS 'EQL encrypted smallint (storage only)';

  --! @brief Encrypted domain public.{{prefix}}_smallint_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_smallint_eq' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_smallint_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_smallint_eq IS 'EQL encrypted smallint (equality)';

  --! @brief Encrypted domain public.{{prefix}}_smallint_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_smallint_ord_ore' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_smallint_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
-- {{#v3}}
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
-- {{/v3}}
-- {{#v4}}
        AND jsonb_typeof(VALUE -> 'ob') = 'string'
        AND left(VALUE ->> 'ob', 4) IN ('0202', '0203')
-- {{/v4}}
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_smallint_ord_ore IS 'EQL encrypted smallint (equality, ordering)';

  --! @brief Encrypted domain public.{{prefix}}_smallint_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_smallint_ord' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_smallint_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
-- {{#v4}}
        AND jsonb_typeof(VALUE -> 'op') = 'string'
        AND left(VALUE ->> 'op', 2) IN ('00', '01')
-- {{/v4}}
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_smallint_ord IS 'EQL encrypted smallint (equality, ordering)';

  --! @brief Encrypted domain public.{{prefix}}_smallint_ord_ope.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_smallint_ord_ope' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_smallint_ord_ope AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'op'
-- {{#v4}}
        AND jsonb_typeof(VALUE -> 'op') = 'string'
        AND left(VALUE ->> 'op', 2) IN ('00', '01')
-- {{/v4}}
        AND VALUE->>'v' = '{{eql_version}}'
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_smallint_ord_ope IS 'EQL encrypted smallint (equality, ordering)';
END
$$;
