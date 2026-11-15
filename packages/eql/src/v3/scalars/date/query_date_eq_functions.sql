-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/query_date_types.sql
-- REQUIRE: src/v3/scalars/date/date_eq_functions.sql

--! @file encrypted_domain/date/query_date_eq_functions.sql
--! @brief Functions for {{prefix}}.query_date_eq.

--! @brief Index extractor for {{prefix}}.query_date_eq.
--! @param a {{prefix}}.query_date_eq
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_date_eq)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a public.{{prefix}}_date_eq
--! @param b {{prefix}}.query_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_date_eq, b {{prefix}}.query_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.=) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a {{prefix}}.query_date_eq
--! @param b public.{{prefix}}_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.=) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a public.{{prefix}}_date_eq
--! @param b {{prefix}}.query_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_date_eq, b {{prefix}}.query_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.<>) {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a {{prefix}}.query_date_eq
--! @param b public.{{prefix}}_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) OPERATOR(pg_catalog.<>) {{prefix}}.eq_term(b) $$;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: public.{{prefix}}_date_ord_ore and {{prefix}}.query_date_eq (mismatched query domain).
--! @param a public.{{prefix}}_date_ord_ore left operand
--! @param b {{prefix}}.query_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_date_ord_ore and {{prefix}}.query_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: {{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_date_eq left operand
--! @param b public.{{prefix}}_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: public.{{prefix}}_date_ord_ore and {{prefix}}.query_date_eq (mismatched query domain).
--! @param a public.{{prefix}}_date_ord_ore left operand
--! @param b {{prefix}}.query_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_date_ord_ore and {{prefix}}.query_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: {{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ore (mismatched query domain).
--! @param a {{prefix}}.query_date_eq left operand
--! @param b public.{{prefix}}_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: public.{{prefix}}_date_ord and {{prefix}}.query_date_eq (mismatched query domain).
--! @param a public.{{prefix}}_date_ord left operand
--! @param b {{prefix}}.query_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_date_ord, b {{prefix}}.query_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_date_ord and {{prefix}}.query_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: {{prefix}}.query_date_eq and public.{{prefix}}_date_ord (mismatched query domain).
--! @param a {{prefix}}.query_date_eq left operand
--! @param b public.{{prefix}}_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_date_eq and public.{{prefix}}_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: public.{{prefix}}_date_ord and {{prefix}}.query_date_eq (mismatched query domain).
--! @param a public.{{prefix}}_date_ord left operand
--! @param b {{prefix}}.query_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_date_ord, b {{prefix}}.query_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_date_ord and {{prefix}}.query_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: {{prefix}}.query_date_eq and public.{{prefix}}_date_ord (mismatched query domain).
--! @param a {{prefix}}.query_date_eq left operand
--! @param b public.{{prefix}}_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_date_eq and public.{{prefix}}_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: public.{{prefix}}_date_ord_ope and {{prefix}}.query_date_eq (mismatched query domain).
--! @param a public.{{prefix}}_date_ord_ope left operand
--! @param b {{prefix}}.query_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_date_ord_ope, b {{prefix}}.query_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.{{prefix}}_date_ord_ope and {{prefix}}.query_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: {{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_date_eq left operand
--! @param b public.{{prefix}}_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', '{{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: public.{{prefix}}_date_ord_ope and {{prefix}}.query_date_eq (mismatched query domain).
--! @param a public.{{prefix}}_date_ord_ope left operand
--! @param b {{prefix}}.query_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_date_ord_ope, b {{prefix}}.query_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.{{prefix}}_date_ord_ope and {{prefix}}.query_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for {{prefix}}.query_date_eq: {{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ope (mismatched query domain).
--! @param a {{prefix}}.query_date_eq left operand
--! @param b public.{{prefix}}_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', '{{prefix}}.query_date_eq and public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;
