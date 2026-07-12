-- Make `authenticator` usable by PostgREST.
--
-- `supabase/postgres` already ships `anon`, `authenticated`, `service_role` and
-- `authenticator`, and `authenticator` is already `LOGIN NOINHERIT` and already a
-- member of the other three. What it does NOT ship is a password (`pg_authid`
-- reports `rolpassword IS NULL`), so PostgREST cannot connect. That is the only
-- thing this file supplies.
--
-- Do NOT reuse `local/postgrest-roles.sql` here. It is written for plain
-- Postgres, where the roles do not exist: its `CREATE ROLE ... IF NOT EXISTS`
-- branch sets the password only on first create, so against an image that
-- already has `authenticator` the password is silently never set and PostgREST
-- fails to authenticate.
--
-- Runs as `supabase_admin` via /docker-entrypoint-initdb.d, which is the image's
-- superuser — and it must, because `authenticator` is a RESERVED role that even
-- the `postgres` role cannot modify (`ERROR: "authenticator" is a reserved role,
-- only superusers can modify it`). It therefore cannot be done from the harness.
--
-- It must also be mounted with a filename that sorts AFTER `migrate.sh`, which is
-- where this image creates the roles. See the compose file.
--
-- Nothing else in the integration harness needs a superuser: the EQL v3 install
-- runs as the non-superuser `postgres` role, exactly as a customer's Supabase
-- project does.

ALTER ROLE authenticator WITH LOGIN PASSWORD 'authpass' NOINHERIT;

-- Idempotent no-ops on this image, kept so the file also works against a plain
-- Postgres that has had the roles created some other way.
GRANT anon, authenticated, service_role TO authenticator;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
