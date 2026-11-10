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
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_match.
--! @param a {{prefix}}.query_text_match
--! @param b public.{{prefix}}_text_match
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a {{prefix}}.query_text_match, b public.{{prefix}}_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;
