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
AS $$ SELECT eql_v3.match_term(a) OPERATOR(pg_catalog.@>) eql_v3.match_term(b) AND (pg_catalog.cardinality(eql_v3.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality(eql_v3.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Operator wrapper for eql_v3.query_text_match.
--! @param a eql_v3.query_text_match
--! @param b public.eql_v3_text_match
--! @return boolean
CREATE FUNCTION eql_v3.matches(a eql_v3.query_text_match, b public.eql_v3_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) OPERATOR(pg_catalog.@>) eql_v3.match_term(b) AND (pg_catalog.cardinality(eql_v3.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality(eql_v3.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Unsupported operator blocker for eql_v3.query_text_match: public.eql_v3_text_search_ore and eql_v3.query_text_match (mismatched query domain).
--! @param a public.eql_v3_text_search_ore left operand
--! @param b eql_v3.query_text_match right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_text_search_ore, b eql_v3.query_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.eql_v3_text_search_ore and eql_v3.query_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_match: eql_v3.query_text_match and public.eql_v3_text_search_ore (mismatched query domain).
--! @param a eql_v3.query_text_match left operand
--! @param b public.eql_v3_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a eql_v3.query_text_match, b public.eql_v3_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'eql_v3.query_text_match and public.eql_v3_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_match: public.eql_v3_text_search and eql_v3.query_text_match (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_match right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_text_search, b eql_v3.query_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.eql_v3_text_search and eql_v3.query_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_match: eql_v3.query_text_match and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_match left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a eql_v3.query_text_match, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'eql_v3.query_text_match and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;
