--! @file v3/schema.sql
--! @brief EQL v3 schema creation
--!
--! Creates the {{prefix}} and {{prefix}}_internal schemas. User-column encrypted
--! domains (public.{{prefix}}_integer, public.{{prefix}}_bigint, and future scalar domains) live in
--! public so application tables survive EQL schema uninstall. {{prefix}} is the
--! public API for index-term extractors, aggregates, AND the operator-backing
--! comparison wrappers
--! (eq/neq/lt/lte/gt/gte/contains/contained_by, plus the jsonb containment
--! helpers). The wrappers are public because they are the function-form
--! equivalent of every supported operator: platforms without operator support
--! (Supabase/PostgREST calls functions, not operators) invoke them by name.
--! {{prefix}}_internal houses INTERNAL implementation objects only: the
--! searchable-encrypted-metadata (SEM) index-term types
--! ({{prefix}}_internal.hmac_256, {{prefix}}_internal.ore_block_256) and their support
--! functions, the unsupported-operator blockers (which only raise), and the
--! aggregate state functions. Together the two schemas are self-contained —
--! they own every type they need and have no runtime dependency on another EQL
--! schema.
--!
--! Drops existing schema if present to support clean reinstallation.
--!
--! @warning DROP SCHEMA CASCADE will remove all objects in the schema
--! @note {{prefix}} is a new, additional schema for the encrypted-domain families.
--!
--! @note DESIGN DECISION — EQL never grants permissions automatically. This
--!       installer issues no GRANT (or REVOKE) on {{prefix}} or {{prefix}}_internal:
--!       access is strictly opt-in. A deployment that exposes EQL to
--!       non-owner roles (e.g. Supabase `authenticated`/`anon` via PostgREST)
--!       must explicitly `GRANT USAGE ON SCHEMA {{prefix}}` and `GRANT EXECUTE` on
--!       the functions it needs. This is intentional least-privilege, not an
--!       oversight — see docs/reference/permissions.md. {{prefix}}_internal is not
--!       part of the public API and normally needs no grant; where a caller
--!       reaches an internal object indirectly (a public operator/aggregate
--!       whose backing state-fn/blocker lives there), grant it deliberately.

--! @brief Drop existing EQL v3 schema
--! @warning CASCADE will drop all dependent objects
DROP SCHEMA IF EXISTS {{prefix}} CASCADE;

--! @brief Create EQL v3 schema
--! @note Houses the encrypted-domain type families
CREATE SCHEMA {{prefix}};

--! @brief Drop existing EQL v3 internal schema
--! @warning CASCADE will drop all dependent objects
DROP SCHEMA IF EXISTS {{prefix}}_internal CASCADE;

--! @brief Create EQL v3 internal implementation schema
--! @note Houses INTERNAL {{prefix}} objects only: SEM index-term TYPES + their
--!       support/constructor/comparator functions, the unsupported-operator
--!       blockers (which only raise), the aggregate state functions, and the
--!       SteVec CHECK validators. Kept out of the public `{{prefix}}` surface so
--!       internal index-term TYPES do not clutter the Supabase Table Builder
--!       type picker. NOTE: the operator-backing comparison *wrappers* are NOT
--!       here — they are public in `{{prefix}}` so every operator has a callable
--!       function equivalent for platforms without operator support.
CREATE SCHEMA {{prefix}}_internal;
COMMENT ON SCHEMA {{prefix}}_internal IS
  'EQL internal implementation detail; not a public API surface.';

--! @brief Schemas owned by the {{prefix}} surface
--!
--! Single source of truth for tooling that must enumerate every schema this
--! installer owns (`{{prefix}}.lints()`, `tasks/pin_search_path_v3.sql`), so a
--! future third {{prefix}}-family schema is one array literal to edit instead of
--! a hardcoded schema-name predicate repeated at every call site. Keep in
--! sync with the `SCHEMA` / `INTERNAL_SCHEMA` constants in
--! `crates/eql-codegen/src/consts.rs` — those drive what codegen emits into
--! each schema; this drives what tooling scans across both.
--!
--! @return name[] The schema names {{prefix}} owns (public + internal).
CREATE FUNCTION {{prefix}}_internal.owned_schemas()
  RETURNS name[]
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT ARRAY['{{prefix}}', '{{prefix}}_internal']::name[]
$$;
