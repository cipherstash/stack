-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/hmac_256/types.sql

--! @file v3/sem/hmac_256/functions.sql
--! @brief HMAC-SHA256 index-term extraction from a jsonb payload (eql_v3 SEM).
--!
--! jsonb-only subset of src/hmac_256/functions.sql. The encrypted-column and
--! ste_vec-entry overloads are intentionally omitted — the eql_v3 scalar
--! domains extract from the jsonb payload directly via a cast to the domain.
--! (Doc comments deliberately avoid naming eql_v2 symbols so the
--! self-containment grep stays clean.)

--! @brief Extract HMAC-SHA256 index term from JSONB payload
--!
--! Inlinable single-statement SQL — the planner can fold this into the calling
--! query so functional hash/btree indexes built on `eql_v3_internal.eq_term(col)`
--! (which calls this) engage structurally.
--!
--! @param val jsonb containing encrypted EQL payload
--! @return eql_v3_internal.hmac_256 HMAC-SHA256 hash value, or NULL when `hm` is absent
CREATE FUNCTION eql_v3_internal.hmac_256(val jsonb)
  RETURNS eql_v3_internal.hmac_256
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (val ->> 'hm')::eql_v3_internal.hmac_256
$$;


--! @brief Check if JSONB payload contains HMAC-SHA256 index term
--!
--! @param val jsonb containing encrypted EQL payload
--! @return boolean True if 'hm' field is present and non-null
CREATE FUNCTION eql_v3_internal.has_hmac_256(val jsonb)
  RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (val ->> 'hm') IS NOT NULL
$$;
