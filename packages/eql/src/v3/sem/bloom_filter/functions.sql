-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/bloom_filter/types.sql

--! @file v3/sem/bloom_filter/functions.sql
--! @brief Extractor for the eql_v3 Bloom-filter SEM index term.
--!
--! jsonb-only subset of src/bloom_filter/functions.sql. The encrypted-column
--! overloads are intentionally omitted — the eql_v3 scalar domains extract from
--! the jsonb payload directly via a cast to the domain. (Doc comments
--! deliberately avoid naming eql_v2 symbols so the self-containment grep stays
--! clean.)

--! @brief Test whether a jsonb payload carries a Bloom-filter (`bf`) term.
--!
--! @param val jsonb The encrypted payload.
--! @return boolean True when the `bf` key is present and non-null.
--!
--! @internal Defined for parity with the eql_v3 SEM index-term predicates
--! (`has_hmac_256` / `has_ore_block_256`); it is not currently called by
--! the extractor below, which gates on value-shape inline, nor by the generated
--! domain CHECK, which tests `bf` presence via the envelope-key skeleton. Kept
--! as the canonical presence test for callers that need one.
CREATE FUNCTION eql_v3_internal.has_bloom_filter(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN val ? 'bf' AND val ->> 'bf' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract the Bloom-filter index term from a jsonb payload.
--!
--! Inlinable single-statement SQL — the planner can fold this into the calling
--! query so the functional GIN index built on `eql_v3_internal.match_term(col)` (which
--! calls this) engages structurally. Mirrors `eql_v3_internal.hmac_256(jsonb)`: no RAISE
--! and no pinned `search_path`. Returns NULL when `bf` is absent or present but
--! not a json array, rather than raising. The `text_match` domain CHECK
--! guarantees the `bf` *key* is present but not that it is an array, so a
--! non-array `bf` (e.g. `{"bf": null}`) can reach here even on a typed value;
--! gating on `jsonb_typeof(...) = 'array'` returns NULL for that case — and for
--! raw jsonb outside the domain — instead of erroring inside
--! `jsonb_array_elements`. NULL, like the HMAC extractor, is the right answer. An
--! empty `bf` array yields an empty filter (contains nothing, contained by
--! everything), matching set-containment semantics.
--!
--! @param val jsonb The encrypted payload.
--! @return eql_v3_internal.bloom_filter The `bf` array as a smallint[] domain value, or
--!   NULL when `bf` is absent or not a json array.
CREATE FUNCTION eql_v3_internal.bloom_filter(val jsonb)
  RETURNS eql_v3_internal.bloom_filter
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE WHEN jsonb_typeof(val -> 'bf') = 'array'
    THEN ARRAY(SELECT jsonb_array_elements(val -> 'bf'))::eql_v3_internal.bloom_filter
  END
$$;
