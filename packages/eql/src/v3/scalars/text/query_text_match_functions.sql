-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_match_functions.sql

--! @file encrypted_domain/text/query_text_match_functions.sql
--! @brief Functions for eql_v3.query_text_match.

--! @brief Index extractor for eql_v3.query_text_match.
--! @param a eql_v3.query_text_match
--! @return eql_v3_internal.bloom_filter
CREATE FUNCTION eql_v3.match_term(a eql_v3.query_text_match)
RETURNS eql_v3_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_text_match.
--! @param a public.eql_v3_text_match
--! @param b eql_v3.query_text_match
--! @return boolean
CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_match, b eql_v3.query_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a)) = 0) $$;

--! @brief Operator wrapper for eql_v3.query_text_match.
--! @param a eql_v3.query_text_match
--! @param b public.eql_v3_text_match
--! @return boolean
CREATE FUNCTION eql_v3.matches(a eql_v3.query_text_match, b public.eql_v3_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a)) = 0) $$;
