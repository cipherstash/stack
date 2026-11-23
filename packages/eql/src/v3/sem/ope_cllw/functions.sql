-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql

--! @file v3/sem/ope_cllw/functions.sql
--! @brief CLLW OPE index-term extraction from a jsonb payload ({{prefix}} SEM).

--! @brief Extract CLLW OPE index term from JSONB payload
--!
--! Returns the CLLW OPE ciphertext from the `op` field of an encrypted scalar
--! payload, hex-decoded to the bytea-backed {{prefix}}_internal.ope_cllw domain.
--!
--! Inlinable single-statement SQL — the body is a strict expression of the
--! argument (`->>` and `decode` are both STRICT), so the planner folds this
--! into the calling query and functional btree indexes built on
--! `{{prefix}}.ord_term(col)` (which calls this) engage structurally, the
--! same way the hmac_256 equality chain does.
--!
--! **Missing-`op` semantics**: `val ->> 'op'` is NULL when `op` is absent and
--! the strict chain propagates it, so the extractor returns SQL NULL and
--! btree's NULL handling filters those rows from range queries.
--!
--! @param val jsonb containing encrypted EQL payload
--! @return {{prefix}}_internal.ope_cllw Hex-decoded CLLW OPE term, or NULL when `op` is
--!         absent
CREATE FUNCTION {{prefix}}_internal.ope_cllw(val jsonb)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT decode(val ->> 'op', 'hex')::{{prefix}}_internal.ope_cllw
$$;

COMMENT ON FUNCTION {{prefix}}_internal.ope_cllw(jsonb) IS
  'eql-inline-critical: raw-jsonb CLLW OPE extractor; must stay inlinable (unpinned search_path)';
