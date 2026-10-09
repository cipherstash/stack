-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_search_ore_functions.sql

--! @file encrypted_domain/text/query_text_search_ore_functions.sql
--! @brief Functions for {{prefix}}.query_text_search_ore.

--! @brief Index extractor for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_text_search_ore)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Index extractor for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @return {{prefix}}_internal.ore_block_256
CREATE FUNCTION {{prefix}}.ord_term_ore(a {{prefix}}.query_text_search_ore)
RETURNS {{prefix}}_internal.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ore_block_256(a::jsonb) $$;

--! @brief Index extractor for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @return {{prefix}}_internal.bloom_filter
CREATE FUNCTION {{prefix}}.match_term(a {{prefix}}.query_text_search_ore)
RETURNS {{prefix}}_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) < {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) < {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) <= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) <= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) > {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) > {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) >= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) >= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;
