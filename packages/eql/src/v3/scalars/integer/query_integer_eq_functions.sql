-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/integer/query_integer_types.sql
-- REQUIRE: src/v3/scalars/integer/integer_eq_functions.sql

--! @file encrypted_domain/integer/query_integer_eq_functions.sql
--! @brief Functions for eql_v3.query_integer_eq.

--! @brief Index extractor for eql_v3.query_integer_eq.
--! @param a eql_v3.query_integer_eq
--! @return eql_v3_internal.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.query_integer_eq)
RETURNS eql_v3_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_integer_eq.
--! @param a public.eql_v3_integer_eq
--! @param b eql_v3.query_integer_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_integer_eq, b eql_v3.query_integer_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_integer_eq.
--! @param a eql_v3.query_integer_eq
--! @param b public.eql_v3_integer_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_integer_eq, b public.eql_v3_integer_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_integer_eq.
--! @param a public.eql_v3_integer_eq
--! @param b eql_v3.query_integer_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_integer_eq, b eql_v3.query_integer_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_integer_eq.
--! @param a eql_v3.query_integer_eq
--! @param b public.eql_v3_integer_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_integer_eq, b public.eql_v3_integer_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: public.eql_v3_integer_ord_ore and eql_v3.query_integer_eq (mismatched query domain).
--! @param a public.eql_v3_integer_ord_ore left operand
--! @param b eql_v3.query_integer_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_integer_ord_ore, b eql_v3.query_integer_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_integer_ord_ore and eql_v3.query_integer_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: eql_v3.query_integer_eq and public.eql_v3_integer_ord_ore (mismatched query domain).
--! @param a eql_v3.query_integer_eq left operand
--! @param b public.eql_v3_integer_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_integer_eq, b public.eql_v3_integer_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_integer_eq and public.eql_v3_integer_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: public.eql_v3_integer_ord_ore and eql_v3.query_integer_eq (mismatched query domain).
--! @param a public.eql_v3_integer_ord_ore left operand
--! @param b eql_v3.query_integer_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_integer_ord_ore, b eql_v3.query_integer_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_integer_ord_ore and eql_v3.query_integer_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: eql_v3.query_integer_eq and public.eql_v3_integer_ord_ore (mismatched query domain).
--! @param a eql_v3.query_integer_eq left operand
--! @param b public.eql_v3_integer_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_integer_eq, b public.eql_v3_integer_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_integer_eq and public.eql_v3_integer_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: public.eql_v3_integer_ord and eql_v3.query_integer_eq (mismatched query domain).
--! @param a public.eql_v3_integer_ord left operand
--! @param b eql_v3.query_integer_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_integer_ord, b eql_v3.query_integer_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_integer_ord and eql_v3.query_integer_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: eql_v3.query_integer_eq and public.eql_v3_integer_ord (mismatched query domain).
--! @param a eql_v3.query_integer_eq left operand
--! @param b public.eql_v3_integer_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_integer_eq, b public.eql_v3_integer_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_integer_eq and public.eql_v3_integer_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: public.eql_v3_integer_ord and eql_v3.query_integer_eq (mismatched query domain).
--! @param a public.eql_v3_integer_ord left operand
--! @param b eql_v3.query_integer_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_integer_ord, b eql_v3.query_integer_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_integer_ord and eql_v3.query_integer_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: eql_v3.query_integer_eq and public.eql_v3_integer_ord (mismatched query domain).
--! @param a eql_v3.query_integer_eq left operand
--! @param b public.eql_v3_integer_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_integer_eq, b public.eql_v3_integer_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_integer_eq and public.eql_v3_integer_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: public.eql_v3_integer_ord_ope and eql_v3.query_integer_eq (mismatched query domain).
--! @param a public.eql_v3_integer_ord_ope left operand
--! @param b eql_v3.query_integer_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_integer_ord_ope, b eql_v3.query_integer_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_integer_ord_ope and eql_v3.query_integer_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: eql_v3.query_integer_eq and public.eql_v3_integer_ord_ope (mismatched query domain).
--! @param a eql_v3.query_integer_eq left operand
--! @param b public.eql_v3_integer_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_integer_eq, b public.eql_v3_integer_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_integer_eq and public.eql_v3_integer_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: public.eql_v3_integer_ord_ope and eql_v3.query_integer_eq (mismatched query domain).
--! @param a public.eql_v3_integer_ord_ope left operand
--! @param b eql_v3.query_integer_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_integer_ord_ope, b eql_v3.query_integer_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_integer_ord_ope and eql_v3.query_integer_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_integer_eq: eql_v3.query_integer_eq and public.eql_v3_integer_ord_ope (mismatched query domain).
--! @param a eql_v3.query_integer_eq left operand
--! @param b public.eql_v3_integer_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_integer_eq, b public.eql_v3_integer_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_integer_eq and public.eql_v3_integer_ord_ope'; END; $$
LANGUAGE plpgsql;
