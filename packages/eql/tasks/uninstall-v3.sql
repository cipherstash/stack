-- Uninstall the standalone {{prefix}} surface. CASCADE removes the domains, SEM
-- types, operators, opclass, and any columns typed with the {{prefix}} domains.
DROP SCHEMA IF EXISTS {{prefix}} CASCADE;

-- Drop the internal implementation schema after {{prefix}} ({{prefix}}'s extractors and
-- operators depend on {{prefix}}_internal types; dropping {{prefix}} first with CASCADE
-- removes those dependents, then {{prefix}}_internal drops cleanly).
DROP SCHEMA IF EXISTS {{prefix}}_internal CASCADE;
