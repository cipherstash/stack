-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_match_functions.sql

--! @file encrypted_domain/text/query_text_match_functions.sql
--! @brief Functions for {{prefix}}.query_text_match.

--! @brief Index extractor for {{prefix}}.query_text_match.
--! @param a {{prefix}}.query_text_match
--! @return {{prefix}}_internal.bloom_filter
CREATE FUNCTION {{prefix}}.match_term(a {{prefix}}.query_text_match)
RETURNS {{prefix}}_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_match.
--! @param a public.{{prefix}}_text_match
--! @param b {{prefix}}.query_text_match
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a public.{{prefix}}_text_match, b {{prefix}}.query_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) OPERATOR(pg_catalog.@>) {{prefix}}.match_term(b) AND (pg_catalog.cardinality({{prefix}}.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality({{prefix}}.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_match.
--! @param a {{prefix}}.query_text_match
--! @param b public.{{prefix}}_text_match
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a {{prefix}}.query_text_match, b public.{{prefix}}_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) OPERATOR(pg_catalog.@>) {{prefix}}.match_term(b) AND (pg_catalog.cardinality({{prefix}}.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality({{prefix}}.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_match: public.{{prefix}}_text_search_ore and {{prefix}}.query_text_match (mismatched query domain).
--! @param a public.{{prefix}}_text_search_ore left operand
--! @param b {{prefix}}.query_text_match right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.{{prefix}}_text_search_ore and {{prefix}}.query_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_match: {{prefix}}.query_text_match and public.{{prefix}}_text_search_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_match left operand
--! @param b public.{{prefix}}_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a {{prefix}}.query_text_match, b public.{{prefix}}_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', '{{prefix}}.query_text_match and public.{{prefix}}_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_match: public.{{prefix}}_text_search and {{prefix}}.query_text_match (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_match right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text_search, b {{prefix}}.query_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.{{prefix}}_text_search and {{prefix}}.query_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_match: {{prefix}}.query_text_match and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_match left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a {{prefix}}.query_text_match, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', '{{prefix}}.query_text_match and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;
