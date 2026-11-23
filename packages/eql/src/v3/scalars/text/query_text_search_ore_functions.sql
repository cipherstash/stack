-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_search_ore_functions.sql
-- REQUIRE: src/v3/scalars/functions.sql

--! @file encrypted_domain/text/query_text_search_ore_functions.sql
--! @brief Functions for {{prefix}}.query_text_search_ore.

--! @brief Index extractor for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @return {{prefix}}_internal.hmac_256
-- {{#v4}}
--! @throws When the operand carries no `hm` term, the term = and <> compare.
-- {{/v4}}
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_text_search_ore)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
-- {{#v3}}
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;
-- {{/v3}}
-- {{#v4}}
AS $$ SELECT {{prefix}}_internal.hmac_256({{prefix}}_internal.require_query_term(a::jsonb, '{{prefix}}.query_text_search_ore', 'hm', '= and <>')) $$;
-- {{/v4}}

--! @brief Index extractor for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @return {{prefix}}_internal.{{ore_block}}
-- {{#v4}}
--! @throws When the operand carries no `ob` term, the term <, <=, > and >= compare.
-- {{/v4}}
CREATE FUNCTION {{prefix}}.ord_term_ore(a {{prefix}}.query_text_search_ore)
RETURNS {{prefix}}_internal.{{ore_block}}
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
-- {{#v3}}
AS $$ SELECT {{prefix}}_internal.{{ore_block}}(a::jsonb) $$;
-- {{/v3}}
-- {{#v4}}
AS $$ SELECT {{prefix}}_internal.{{ore_block}}({{prefix}}_internal.require_query_term(a::jsonb, '{{prefix}}.query_text_search_ore', 'ob', '<, <=, > and >=')) $$;
-- {{/v4}}

--! @brief Index extractor for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @return {{prefix}}_internal.bloom_filter
-- {{#v4}}
--! @throws When the operand carries no `bf` term, the term @@ compare.
-- {{/v4}}
CREATE FUNCTION {{prefix}}.match_term(a {{prefix}}.query_text_search_ore)
RETURNS {{prefix}}_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
-- {{#v3}}
AS $$ SELECT {{prefix}}_internal.bloom_filter(a::jsonb) $$;
-- {{/v3}}
-- {{#v4}}
AS $$ SELECT {{prefix}}_internal.bloom_filter({{prefix}}_internal.require_query_term(a::jsonb, '{{prefix}}.query_text_search_ore', 'bf', '@@')) $$;
-- {{/v4}}

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.=) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.=) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.<>) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.<>) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a public.{{prefix}}_text_search_ore
--! @param b {{prefix}}.query_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a public.{{prefix}}_text_search_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) OPERATOR(pg_catalog.@>) {{prefix}}.match_term(b) AND (pg_catalog.cardinality({{prefix}}.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality({{prefix}}.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_search_ore.
--! @param a {{prefix}}.query_text_search_ore
--! @param b public.{{prefix}}_text_search_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) OPERATOR(pg_catalog.@>) {{prefix}}.match_term(b) AND (pg_catalog.cardinality({{prefix}}.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality({{prefix}}.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_eq and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_eq left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text_eq, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_text_eq and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_eq (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_eq and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_eq left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text_eq, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_text_eq and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_eq (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_match and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_match left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text_match, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.{{prefix}}_text_match and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_match (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_match right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ore left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text_ord_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ore left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text_ord_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ore left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_text_ord_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ore left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_text_ord_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ore left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_text_ord_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ore left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_text_ord_ore, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.{{prefix}}_text_ord_ore and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.{{prefix}}_text_ord and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ope left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text_ord_ope, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ope left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text_ord_ope, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ope left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_text_ord_ope, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ope left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_text_ord_ope, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ope left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_text_ord_ope, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_ord_ope left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_text_ord_ope, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.{{prefix}}_text_ord_ope and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore (mismatched query domain).
--! @param a public.{{prefix}}_text_search left operand
--! @param b {{prefix}}.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text_search, b {{prefix}}.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.{{prefix}}_text_search and {{prefix}}.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_text_search_ore: {{prefix}}.query_text_search_ore and public.{{prefix}}_text_search (mismatched query domain).
--! @param a {{prefix}}.query_text_search_ore left operand
--! @param b public.{{prefix}}_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal."@@"(a {{prefix}}.query_text_search_ore, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', '{{prefix}}.query_text_search_ore and public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;
