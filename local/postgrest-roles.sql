-- Roles PostgREST needs, created at database init.
--
-- `authenticator` is the role PostgREST CONNECTS as; it must be able to
-- `SET ROLE` to `anon`, so it is a member of it and NOINHERIT (it gets anon's
-- rights only after switching, never ambiently). This is PostgREST's documented
-- convention and it is what makes the live suite exercise the Supabase grants
-- rather than the owner's ambient superuser rights — pointing
-- PGRST_DB_ANON_ROLE at the owner would make every permission check pass
-- vacuously and prove nothing.
--
-- `postgres` exists only because the shipped grants block says
-- `ALTER DEFAULT PRIVILEGES FOR ROLE postgres`; a plain Postgres image has no
-- such role.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    CREATE ROLE service_role NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN
    CREATE ROLE postgres NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticator') THEN
    CREATE ROLE authenticator LOGIN PASSWORD 'authpass' NOINHERIT;
  END IF;
END
$$;

GRANT anon, authenticated TO authenticator;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
