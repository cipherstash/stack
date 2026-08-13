-- REQUIRE: src/v3/schema.sql

--! @file v3/crypto.sql
--! @brief PostgreSQL pgcrypto extension enablement (eql_v3 fork)
--!
--! Forked from src/crypto.sql (design D8) so the entire eql_v3 dependency
--! closure lives under src/v3/. Enables the pgcrypto extension which provides
--! cryptographic functions used by the eql_v3 ORE comparison path.
--!
--! Installs pgcrypto into the `extensions` schema (Supabase convention) to
--! avoid the `extension_in_public` lint. Every EQL function that uses pgcrypto
--! has `pg_catalog, extensions, public` on its `search_path`, so a pre-existing
--! install in `public` keeps working — and a pre-existing install anywhere else
--! will be rejected at install time. The body is idempotent
--! (`CREATE SCHEMA IF NOT EXISTS`, `pg_extension` guard), so running it
--! alongside the eql_v2 copy in a combined install is safe.
--!
--! @note pgcrypto provides functions like digest(), hmac(), gen_random_bytes()

--! @brief Create extensions schema (Supabase convention)
CREATE SCHEMA IF NOT EXISTS extensions;

--! @brief Enable pgcrypto extension and validate its schema
DO $$
DECLARE
  pgcrypto_schema name;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
    CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
  END IF;

  SELECT n.nspname INTO pgcrypto_schema
  FROM pg_extension e
  JOIN pg_namespace n ON n.oid = e.extnamespace
  WHERE e.extname = 'pgcrypto';

  IF pgcrypto_schema = 'extensions' THEN
    -- expected location, nothing to say
    NULL;
  ELSIF pgcrypto_schema = 'public' THEN
    RAISE NOTICE
      'pgcrypto is installed in the `public` schema. EQL works against this layout, '
      'but Supabase splinter will flag it as `extension_in_public`. Move it with: '
      'ALTER EXTENSION pgcrypto SET SCHEMA extensions';
  ELSE
    RAISE EXCEPTION
      'pgcrypto is installed in schema `%`, which is not on the EQL function search_path '
      '(pg_catalog, extensions, public). EQL cryptographic operations would fail at '
      'runtime. Relocate the extension before installing EQL: '
      'ALTER EXTENSION pgcrypto SET SCHEMA extensions',
      pgcrypto_schema;
  END IF;
END $$;
