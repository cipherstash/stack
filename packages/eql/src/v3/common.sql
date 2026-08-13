-- REQUIRE: src/v3/schema.sql

--! @file v3/common.sql
--! @brief Common utility functions for the self-contained eql_v3 surface.
--!
--! Forked from src/common.sql (design D7) so the eql_v3 ORE constructor owns the
--! one transitive helper it needs without reaching into another schema. The
--! eql_v2 original is unchanged.

--! @brief Convert JSONB hex array to bytea array
--! @internal
--!
--! Converts a JSONB array of hex-encoded strings into a PostgreSQL bytea array.
--! Used for deserializing binary data (like ORE terms) from JSONB storage.
--!
--! @param val jsonb JSONB array of hex-encoded strings
--! @return bytea[] Array of decoded binary values
--!
--! @note Returns NULL if input is JSON null
--! @note Each array element is hex-decoded to bytea
--! @note plpgsql, not `LANGUAGE sql` (issue #353). This helper's ONLY caller
--!   chain is `ore_block_256(val)` -> `jsonb_array_to_ore_block_256(val)` —
--!   both reached exclusively from plpgsql and btree operator-class support
--!   contexts, where SQL functions can NEVER be inlined and instead pay the
--!   per-call SQL-function executor (measured 3.5x the per-call cost of the
--!   plpgsql equivalent; +43% on ORE ordered scans end-to-end). plpgsql
--!   caches its plan across calls. The non-array guard preserves the v3
--!   behaviour (returns NULL for a non-array scalar; the v2 plpgsql original
--!   raised) — both callers only ever pass an array or JSON null (`val->'ob'`),
--!   so the divergence stays unreachable in practice; JSON null and empty
--!   array still return NULL exactly as before.
CREATE FUNCTION eql_v3_internal.jsonb_array_to_bytea_array(val jsonb)
RETURNS bytea[]
  IMMUTABLE
AS $$
DECLARE
  result bytea[];
BEGIN
  IF val IS NULL OR jsonb_typeof(val) != 'array' THEN
    RETURN NULL;
  END IF;
  SELECT array_agg(decode(value::text, 'hex')::bytea)
    INTO result
  FROM jsonb_array_elements_text(val) AS value;
  RETURN result;
END;
$$ LANGUAGE plpgsql;

--! @internal Keep the inline-critical marker so the post-install
--! pin_search_path pass leaves this unpinned: a `SET search_path` clause on a
--! plpgsql function forces per-call configuration switching — measurable on a
--! helper invoked per compared value in the ore_block_256 opclass hot path.
--! It takes a bare `jsonb` arg (not a jsonb-backed encrypted DOMAIN), so the
--! structural skip in tasks/pin_search_path_v3.sql does not recognise it;
--! this marker is the documented manual opt-in.
COMMENT ON FUNCTION eql_v3_internal.jsonb_array_to_bytea_array(jsonb) IS
  'eql-inline-critical: per-encrypted-value ORE opclass-path helper; must stay unpinned (SET search_path adds per-call overhead)';
