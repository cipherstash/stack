-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/json/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql

--! @file v3/json/aggregates.sql
--! @brief min / max aggregates over public.{{prefix}}_json_entry.
--!
--! SteVec document entries extracted at a selector (`doc -> 'sel'`) order by
--! their CLLW OPE (`op`) term, so the extremum is picked by comparing
--! `{{prefix}}.ord_term(entry)` rather than the scalar Block-ORE `ord_term` the
--! generated scalar ord aggregates use. The ope_cllw bytea domain orders under
--! native byte comparison, so `<` / `>` on the extracted terms needs no custom
--! comparator. Same STRICT + PARALLEL SAFE shape as the generated scalar
--! `min`/`max` so partial/parallel aggregation is available on large GROUP BY
--! workloads.
--!
--! Per the encrypted-domain footgun rules the state functions are
--! `LANGUAGE plpgsql` with the pinned `search_path` — a `LANGUAGE sql` body would
--! be inlinable and the planner could elide it.
--!
--! @note **Only `op`-carrying entries are orderable.** `{{prefix}}.ord_term(entry)`
--!   returns NULL when an entry has no `op` (CLLW OPE) term — the same entries a
--!   `{{prefix}}.ord_term` btree NULL-filters from range scans. The state functions
--!   therefore IGNORE `op`-less entries (they never become or survive as the
--!   extremum), so `min`/`max` is well-defined over a mix of `op`-carrying and
--!   `op`-less entries and is not corrupted by an `op`-less seed. A naive
--!   `ord_term(value) < ord_term(state)` would be NULL whenever either side
--!   lacks `op`, pinning a wrong (`op`-less) extremum when the first aggregated
--!   row is `op`-less. An all-`op`-less input has no orderable extremum and
--!   returns the (arbitrary) STRICT seed.

--! @brief State function for min on public.{{prefix}}_json_entry.
--!
--! Keeps whichever orderable entry has the lesser CLLW OPE term. STRICT, so SQL
--! NULL entries are skipped by the aggregate machinery; `op`-less (non-orderable)
--! entries are skipped explicitly (see the @note on this file).
--!
--! @param state public.{{prefix}}_json_entry Running extremum.
--! @param value public.{{prefix}}_json_entry Candidate entry.
--! @return public.{{prefix}}_json_entry The lesser orderable entry by `ord_term`.
CREATE FUNCTION {{prefix}}_internal.jsonb_entry_min_sfunc(
  state public.{{prefix}}_json_entry,
  value public.{{prefix}}_json_entry
)
RETURNS public.{{prefix}}_json_entry
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  value_ope {{prefix}}_internal.ope_cllw := {{prefix}}.ord_term(value);
  state_ope {{prefix}}_internal.ope_cllw := {{prefix}}.ord_term(state);
BEGIN
  -- A non-orderable (op-less) candidate never replaces the running extremum.
  IF value_ope IS NULL THEN
    RETURN state;
  END IF;
  -- Adopt the candidate when the running extremum is itself non-orderable
  -- (e.g. an op-less STRICT seed) or strictly greater.
  IF state_ope IS NULL OR value_ope < state_ope THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate over public.{{prefix}}_json_entry.
--! @param input public.{{prefix}}_json_entry
--! @return public.{{prefix}}_json_entry The entry with the smallest CLLW OPE term.
CREATE AGGREGATE {{prefix}}.min(public.{{prefix}}_json_entry) (
  sfunc = {{prefix}}_internal.jsonb_entry_min_sfunc,
  stype = public.{{prefix}}_json_entry,
  combinefunc = {{prefix}}_internal.jsonb_entry_min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.{{prefix}}_json_entry.
--!
--! Keeps whichever orderable entry has the greater CLLW OPE term. `op`-less
--! entries are skipped, mirroring `jsonb_entry_min_sfunc` (see the file @note).
--!
--! @param state public.{{prefix}}_json_entry Running extremum.
--! @param value public.{{prefix}}_json_entry Candidate entry.
--! @return public.{{prefix}}_json_entry The greater orderable entry by `ord_term`.
CREATE FUNCTION {{prefix}}_internal.jsonb_entry_max_sfunc(
  state public.{{prefix}}_json_entry,
  value public.{{prefix}}_json_entry
)
RETURNS public.{{prefix}}_json_entry
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  value_ope {{prefix}}_internal.ope_cllw := {{prefix}}.ord_term(value);
  state_ope {{prefix}}_internal.ope_cllw := {{prefix}}.ord_term(state);
BEGIN
  -- A non-orderable (op-less) candidate never replaces the running extremum.
  IF value_ope IS NULL THEN
    RETURN state;
  END IF;
  -- Adopt the candidate when the running extremum is itself non-orderable
  -- (e.g. an op-less STRICT seed) or strictly lesser.
  IF state_ope IS NULL OR value_ope > state_ope THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate over public.{{prefix}}_json_entry.
--! @param input public.{{prefix}}_json_entry
--! @return public.{{prefix}}_json_entry The entry with the largest CLLW OPE term.
CREATE AGGREGATE {{prefix}}.max(public.{{prefix}}_json_entry) (
  sfunc = {{prefix}}_internal.jsonb_entry_max_sfunc,
  stype = public.{{prefix}}_json_entry,
  combinefunc = {{prefix}}_internal.jsonb_entry_max_sfunc,
  parallel = safe
);
