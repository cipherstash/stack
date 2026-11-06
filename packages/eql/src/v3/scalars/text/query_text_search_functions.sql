-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_search_functions.sql
-- REQUIRE: src/v3/scalars/functions.sql

--! @file encrypted_domain/text/query_text_search_functions.sql
--! @brief Functions for {{prefix}}.query_text_search.

--! @brief Index extractor for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @return {{prefix}}_internal.hmac_256
-- {{#v4}}
--! @throws When the operand carries no `hm` term, the term = and <> compare.
-- {{/v4}}
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_text_search)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
-- {{#v3}}
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;
-- {{/v3}}
-- {{#v4}}
AS $$ SELECT {{prefix}}_internal.hmac_256({{prefix}}_internal.require_query_term(a::jsonb, '{{prefix}}.query_text_search', 'hm', '= and <>')) $$;
-- {{/v4}}

--! @brief Index extractor for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @return {{prefix}}_internal.ope_cllw
-- {{#v4}}
--! @throws When the operand carries no `op` term, the term <, <=, > and >= compare.
-- {{/v4}}
CREATE FUNCTION {{prefix}}.ord_term(a {{prefix}}.query_text_search)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
-- {{#v3}}
AS $$ SELECT {{prefix}}_internal.ope_cllw(a::jsonb) $$;
-- {{/v3}}
-- {{#v4}}
AS $$ SELECT {{prefix}}_internal.ope_cllw({{prefix}}_internal.require_query_term(a::jsonb, '{{prefix}}.query_text_search', 'op', '<, <=, > and >=')) $$;
-- {{/v4}}

--! @brief Index extractor for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @return {{prefix}}_internal.bloom_filter
-- {{#v4}}
--! @throws When the operand carries no `bf` term, the term @@ compare.
-- {{/v4}}
CREATE FUNCTION {{prefix}}.match_term(a {{prefix}}.query_text_search)
RETURNS {{prefix}}_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
-- {{#v3}}
AS $$ SELECT {{prefix}}_internal.bloom_filter(a::jsonb) $$;
-- {{/v3}}
-- {{#v4}}
AS $$ SELECT {{prefix}}_internal.bloom_filter({{prefix}}_internal.require_query_term(a::jsonb, '{{prefix}}.query_text_search', 'bf', '@@')) $$;
-- {{/v4}}

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b {{prefix}}.query_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search.
--! @param a {{prefix}}.query_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a {{prefix}}.query_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;
