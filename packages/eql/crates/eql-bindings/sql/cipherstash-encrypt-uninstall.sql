-- Uninstall the standalone eql_v3 surface. CASCADE removes the domains, SEM
-- types, operators, opclass, and any columns typed with the eql_v3 domains.
DROP SCHEMA IF EXISTS eql_v3 CASCADE;

-- Drop the internal implementation schema after eql_v3 (eql_v3's extractors and
-- operators depend on eql_v3_internal types; dropping eql_v3 first with CASCADE
-- removes those dependents, then eql_v3_internal drops cleanly).
DROP SCHEMA IF EXISTS eql_v3_internal CASCADE;
