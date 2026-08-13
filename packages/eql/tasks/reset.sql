-- !!! Only used during tests !!
-- Fully clean out the database between test runs

DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO public;

-- Drop the eql_v3 schema if present; the EQL installer recreates it with a
-- plain `CREATE SCHEMA eql_v3`, so reset must not leave one behind.
DROP SCHEMA IF EXISTS eql_v3 CASCADE;
DROP SCHEMA IF EXISTS eql_v3_internal CASCADE;
