-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/double/query_double_types.sql
-- REQUIRE: src/v3/scalars/double/double_ord_ore_functions.sql

--! @file encrypted_domain/double/query_double_ord_ore_functions.sql
--! @brief Functions for {{prefix}}.query_double_ord_ore.

--! @brief Index extractor for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @return {{prefix}}_internal.{{ore_block}}
CREATE FUNCTION {{prefix}}.ord_term_ore(a {{prefix}}.query_double_ord_ore)
RETURNS {{prefix}}_internal.{{ore_block}}
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.{{ore_block}}(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a public.{{prefix}}_double_ord_ore
--! @param b {{prefix}}.query_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_double_ord_ore, b {{prefix}}.query_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @param b public.{{prefix}}_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a public.{{prefix}}_double_ord_ore
--! @param b {{prefix}}.query_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_double_ord_ore, b {{prefix}}.query_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<>) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @param b public.{{prefix}}_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<>) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a public.{{prefix}}_double_ord_ore
--! @param b {{prefix}}.query_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_double_ord_ore, b {{prefix}}.query_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @param b public.{{prefix}}_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a public.{{prefix}}_double_ord_ore
--! @param b {{prefix}}.query_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_double_ord_ore, b {{prefix}}.query_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @param b public.{{prefix}}_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.<=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a public.{{prefix}}_double_ord_ore
--! @param b {{prefix}}.query_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_double_ord_ore, b {{prefix}}.query_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @param b public.{{prefix}}_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a public.{{prefix}}_double_ord_ore
--! @param b {{prefix}}.query_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_double_ord_ore, b {{prefix}}.query_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_double_ord_ore.
--! @param a {{prefix}}.query_double_ord_ore
--! @param b public.{{prefix}}_double_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) OPERATOR(public.>=) {{prefix}}.ord_term_ore(b) $$;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_eq and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_eq left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_double_eq, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_double_eq and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_eq (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_eq and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_eq left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_double_eq, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_double_eq and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_eq (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_double_ord, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_double_ord, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_double_ord, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_double_ord, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_double_ord, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_double_ord, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.{{prefix}}_double_ord and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord_ope left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_double_ord_ope, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord_ope left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_double_ord_ope, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord_ope left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_double_ord_ope, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord_ope left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_double_ord_ope, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord_ope left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_double_ord_ope, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore (mismatched query domain).
--! @param a public.{{prefix}}_double_ord_ope left operand
--! @param b {{prefix}}.query_double_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_double_ord_ope, b {{prefix}}.query_double_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.{{prefix}}_double_ord_ope and {{prefix}}.query_double_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_double_ord_ore: {{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_double_ord_ore left operand
--! @param b public.{{prefix}}_double_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_double_ord_ore, b public.{{prefix}}_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', '{{prefix}}.query_double_ord_ore and public.{{prefix}}_double_ord_ope'; END; $$
LANGUAGE plpgsql;
