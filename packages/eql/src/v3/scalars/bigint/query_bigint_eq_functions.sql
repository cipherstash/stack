-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/query_bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_eq_functions.sql

--! @file encrypted_domain/bigint/query_bigint_eq_functions.sql
--! @brief Functions for eql_v3.query_bigint_eq.

--! @brief Index extractor for eql_v3.query_bigint_eq.
--! @param a eql_v3.query_bigint_eq
--! @return eql_v3_internal.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.query_bigint_eq)
RETURNS eql_v3_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_eq.
--! @param a public.eql_v3_bigint_eq
--! @param b eql_v3.query_bigint_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_bigint_eq, b eql_v3.query_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_eq.
--! @param a eql_v3.query_bigint_eq
--! @param b public.eql_v3_bigint_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_eq.
--! @param a public.eql_v3_bigint_eq
--! @param b eql_v3.query_bigint_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_bigint_eq, b eql_v3.query_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_eq.
--! @param a eql_v3.query_bigint_eq
--! @param b public.eql_v3_bigint_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Blocker: public.eql_v3_bigint_ord_ore = eql_v3.query_bigint_eq always raises (mismatched query domain).
--! @param a public.eql_v3_bigint_ord_ore left operand
--! @param b eql_v3.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'public.eql_v3_bigint_ord_ore', 'eql_v3.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_bigint_eq = public.eql_v3_bigint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_bigint_eq left operand
--! @param b public.eql_v3_bigint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'eql_v3.query_bigint_eq', 'public.eql_v3_bigint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_bigint_ord_ore <> eql_v3.query_bigint_eq always raises (mismatched query domain).
--! @param a public.eql_v3_bigint_ord_ore left operand
--! @param b eql_v3.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'public.eql_v3_bigint_ord_ore', 'eql_v3.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_bigint_eq <> public.eql_v3_bigint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_bigint_eq left operand
--! @param b public.eql_v3_bigint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'eql_v3.query_bigint_eq', 'public.eql_v3_bigint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_bigint_ord = eql_v3.query_bigint_eq always raises (mismatched query domain).
--! @param a public.eql_v3_bigint_ord left operand
--! @param b eql_v3.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_bigint_ord, b eql_v3.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'public.eql_v3_bigint_ord', 'eql_v3.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_bigint_eq = public.eql_v3_bigint_ord always raises (mismatched query domain).
--! @param a eql_v3.query_bigint_eq left operand
--! @param b public.eql_v3_bigint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'eql_v3.query_bigint_eq', 'public.eql_v3_bigint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_bigint_ord <> eql_v3.query_bigint_eq always raises (mismatched query domain).
--! @param a public.eql_v3_bigint_ord left operand
--! @param b eql_v3.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_bigint_ord, b eql_v3.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'public.eql_v3_bigint_ord', 'eql_v3.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_bigint_eq <> public.eql_v3_bigint_ord always raises (mismatched query domain).
--! @param a eql_v3.query_bigint_eq left operand
--! @param b public.eql_v3_bigint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'eql_v3.query_bigint_eq', 'public.eql_v3_bigint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_bigint_ord_ope = eql_v3.query_bigint_eq always raises (mismatched query domain).
--! @param a public.eql_v3_bigint_ord_ope left operand
--! @param b eql_v3.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_bigint_ord_ope, b eql_v3.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'public.eql_v3_bigint_ord_ope', 'eql_v3.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_bigint_eq = public.eql_v3_bigint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_bigint_eq left operand
--! @param b public.eql_v3_bigint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'eql_v3.query_bigint_eq', 'public.eql_v3_bigint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_bigint_ord_ope <> eql_v3.query_bigint_eq always raises (mismatched query domain).
--! @param a public.eql_v3_bigint_ord_ope left operand
--! @param b eql_v3.query_bigint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_bigint_ord_ope, b eql_v3.query_bigint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'public.eql_v3_bigint_ord_ope', 'eql_v3.query_bigint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_bigint_eq <> public.eql_v3_bigint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_bigint_eq left operand
--! @param b public.eql_v3_bigint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_bigint_eq, b public.eql_v3_bigint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'eql_v3.query_bigint_eq', 'public.eql_v3_bigint_ord_ope'; END; $$
LANGUAGE plpgsql;
