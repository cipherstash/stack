-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/query_bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_eq_functions.sql

--! @file encrypted_domain/bigint/query_bigint_eq_functions.sql
--! @brief Functions for {{prefix}}.query_bigint_eq.

--! @brief Index extractor for {{prefix}}.query_bigint_eq.
--! @param a {{prefix}}.query_bigint_eq
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_bigint_eq)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_bigint_eq.
--! @param a public.{{prefix}}_bigint_eq
--! @param b {{prefix}}.query_bigint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_bigint_eq, b {{prefix}}.query_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.=) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_bigint_eq.
--! @param a {{prefix}}.query_bigint_eq
--! @param b public.{{prefix}}_bigint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.=) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_bigint_eq.
--! @param a public.{{prefix}}_bigint_eq
--! @param b {{prefix}}.query_bigint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_bigint_eq, b {{prefix}}.query_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.<>) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_bigint_eq.
--! @param a {{prefix}}.query_bigint_eq
--! @param b public.{{prefix}}_bigint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.<>) {{prefix}}.eq_term(b) $$;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: public.{{prefix}}_bigint_ord_ore and {{prefix}}.query_bigint_eq (mismatched query domain).
--! @param a public.{{prefix}}_bigint_ord_ore left operand
--! @param b {{prefix}}.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_bigint_ord_ore, b {{prefix}}.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_bigint_ord_ore and {{prefix}}.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: {{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_bigint_eq left operand
--! @param b public.{{prefix}}_bigint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: public.{{prefix}}_bigint_ord_ore and {{prefix}}.query_bigint_eq (mismatched query domain).
--! @param a public.{{prefix}}_bigint_ord_ore left operand
--! @param b {{prefix}}.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_bigint_ord_ore, b {{prefix}}.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_bigint_ord_ore and {{prefix}}.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: {{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_bigint_eq left operand
--! @param b public.{{prefix}}_bigint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: public.{{prefix}}_bigint_ord and {{prefix}}.query_bigint_eq (mismatched query domain).
--! @param a public.{{prefix}}_bigint_ord left operand
--! @param b {{prefix}}.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_bigint_ord, b {{prefix}}.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_bigint_ord and {{prefix}}.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: {{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord (mismatched query domain).
--! @param a {{prefix}}.query_bigint_eq left operand
--! @param b public.{{prefix}}_bigint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: public.{{prefix}}_bigint_ord and {{prefix}}.query_bigint_eq (mismatched query domain).
--! @param a public.{{prefix}}_bigint_ord left operand
--! @param b {{prefix}}.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_bigint_ord, b {{prefix}}.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_bigint_ord and {{prefix}}.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: {{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord (mismatched query domain).
--! @param a {{prefix}}.query_bigint_eq left operand
--! @param b public.{{prefix}}_bigint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: public.{{prefix}}_bigint_ord_ope and {{prefix}}.query_bigint_eq (mismatched query domain).
--! @param a public.{{prefix}}_bigint_ord_ope left operand
--! @param b {{prefix}}.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_bigint_ord_ope, b {{prefix}}.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_bigint_ord_ope and {{prefix}}.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: {{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_bigint_eq left operand
--! @param b public.{{prefix}}_bigint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: public.{{prefix}}_bigint_ord_ope and {{prefix}}.query_bigint_eq (mismatched query domain).
--! @param a public.{{prefix}}_bigint_ord_ope left operand
--! @param b {{prefix}}.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_bigint_ord_ope, b {{prefix}}.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_bigint_ord_ope and {{prefix}}.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_bigint_eq: {{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_bigint_eq left operand
--! @param b public.{{prefix}}_bigint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_bigint_eq, b public.{{prefix}}_bigint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_bigint_eq and public.{{prefix}}_bigint_ord_ope'; END; $$
LANGUAGE plpgsql;
