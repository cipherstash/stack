--! @file v3/schema.sql
--! @brief EQL v3 schema creation
--!
--! Creates the eql_v3 and eql_v3_internal schemas. User-column encrypted
--! domains (public.eql_v3_integer, public.eql_v3_bigint, and future scalar domains) live in
--! public so application tables survive EQL schema uninstall. eql_v3 is the
--! public API for index-term extractors, aggregates, AND the operator-backing
--! comparison wrappers
--! (eq/neq/lt/lte/gt/gte/contains/contained_by, plus the jsonb containment
--! helpers). The wrappers are public because they are the function-form
--! equivalent of every supported operator: platforms without operator support
--! (Supabase/PostgREST calls functions, not operators) invoke them by name.
--! eql_v3_internal houses INTERNAL implementation objects only: the
--! searchable-encrypted-metadata (SEM) index-term types
--! (eql_v3_internal.hmac_256, eql_v3_internal.ore_block_256) and their support
--! functions, the unsupported-operator blockers (which only raise), and the
--! aggregate state functions. Together the two schemas are self-contained —
--! they own every type they need and have no runtime dependency on another EQL
--! schema.
--!
--! Drops existing schema if present to support clean reinstallation.
--!
--! @warning DROP SCHEMA CASCADE will remove all objects in the schema
--! @note eql_v3 is a new, additional schema for the encrypted-domain families.
--!
--! @note DESIGN DECISION — EQL never grants permissions automatically. This
--!       installer issues no GRANT (or REVOKE) on eql_v3 or eql_v3_internal:
--!       access is strictly opt-in. A deployment that exposes EQL to
--!       non-owner roles (e.g. Supabase `authenticated`/`anon` via PostgREST)
--!       must explicitly `GRANT USAGE ON SCHEMA eql_v3` and `GRANT EXECUTE` on
--!       the functions it needs. This is intentional least-privilege, not an
--!       oversight — see docs/reference/permissions.md. eql_v3_internal is not
--!       part of the public API and normally needs no grant; where a caller
--!       reaches an internal object indirectly (a public operator/aggregate
--!       whose backing state-fn/blocker lives there), grant it deliberately.

--! @brief Drop existing EQL v3 schema
--! @warning CASCADE will drop all dependent objects
DROP SCHEMA IF EXISTS eql_v3 CASCADE;

--! @brief Create EQL v3 schema
--! @note Houses the encrypted-domain type families
CREATE SCHEMA eql_v3;

--! @brief Drop existing EQL v3 internal schema
--! @warning CASCADE will drop all dependent objects
DROP SCHEMA IF EXISTS eql_v3_internal CASCADE;

--! @brief Create EQL v3 internal implementation schema
--! @note Houses INTERNAL eql_v3 objects only: SEM index-term TYPES + their
--!       support/constructor/comparator functions, the unsupported-operator
--!       blockers (which only raise), the aggregate state functions, and the
--!       SteVec CHECK validators. Kept out of the public `eql_v3` surface so
--!       internal index-term TYPES do not clutter the Supabase Table Builder
--!       type picker. NOTE: the operator-backing comparison *wrappers* are NOT
--!       here — they are public in `eql_v3` so every operator has a callable
--!       function equivalent for platforms without operator support.
CREATE SCHEMA eql_v3_internal;
COMMENT ON SCHEMA eql_v3_internal IS
  'EQL internal implementation detail; not a public API surface.';

--! @brief Schemas owned by the eql_v3 surface
--!
--! Single source of truth for tooling that must enumerate every schema this
--! installer owns (`eql_v3.lints()`, `tasks/pin_search_path_v3.sql`), so a
--! future third eql_v3-family schema is one array literal to edit instead of
--! a hardcoded schema-name predicate repeated at every call site. Keep in
--! sync with the `SCHEMA` / `INTERNAL_SCHEMA` constants in
--! `crates/eql-codegen/src/consts.rs` — those drive what codegen emits into
--! each schema; this drives what tooling scans across both.
--!
--! @return name[] The schema names eql_v3 owns (public + internal).
CREATE FUNCTION eql_v3_internal.owned_schemas()
  RETURNS name[]
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT ARRAY['eql_v3', 'eql_v3_internal']::name[]
$$;
