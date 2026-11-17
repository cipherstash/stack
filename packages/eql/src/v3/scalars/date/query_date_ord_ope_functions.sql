-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/query_date_types.sql
-- REQUIRE: src/v3/scalars/date/date_ord_ope_functions.sql

--! @file encrypted_domain/date/query_date_ord_ope_functions.sql
--! @brief Functions for eql_v3.query_date_ord_ope.

--! @brief Index extractor for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @return eql_v3_internal.ope_cllw
CREATE FUNCTION eql_v3.ord_term(a eql_v3.query_date_ord_ope)
RETURNS eql_v3_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a public.eql_v3_date_ord_ope
--! @param b eql_v3.query_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_date_ord_ope, b eql_v3.query_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.=) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @param b public.eql_v3_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.=) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a public.eql_v3_date_ord_ope
--! @param b eql_v3.query_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_date_ord_ope, b eql_v3.query_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.<>) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @param b public.eql_v3_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.<>) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a public.eql_v3_date_ord_ope
--! @param b eql_v3.query_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_date_ord_ope, b eql_v3.query_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.<) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @param b public.eql_v3_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.<) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a public.eql_v3_date_ord_ope
--! @param b eql_v3.query_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_date_ord_ope, b eql_v3.query_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.<=) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @param b public.eql_v3_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.<=) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a public.eql_v3_date_ord_ope
--! @param b eql_v3.query_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_date_ord_ope, b eql_v3.query_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.>) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @param b public.eql_v3_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.>) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a public.eql_v3_date_ord_ope
--! @param b eql_v3.query_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_date_ord_ope, b eql_v3.query_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.>=) eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_date_ord_ope.
--! @param a eql_v3.query_date_ord_ope
--! @param b public.eql_v3_date_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) OPERATOR(pg_catalog.>=) eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_eq and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_eq left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_date_eq, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_date_eq and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_eq (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_eq and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_eq left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_date_eq, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_date_eq and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_eq (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_date_ord_ope and public.eql_v3_date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord_ore left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_date_ord_ore, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord_ore left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_date_ord_ore, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord_ore left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_date_ord_ore, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord_ore left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_date_ord_ore, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord_ore left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_date_ord_ore, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord_ore left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_date_ord_ore, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.eql_v3_date_ord_ore and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_date_ord, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_date_ord and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_date_ord, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_date_ord and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_date_ord, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.eql_v3_date_ord and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_date_ord, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.eql_v3_date_ord and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_date_ord, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.eql_v3_date_ord and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: public.eql_v3_date_ord and eql_v3.query_date_ord_ope (mismatched query domain).
--! @param a public.eql_v3_date_ord left operand
--! @param b eql_v3.query_date_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_date_ord, b eql_v3.query_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.eql_v3_date_ord and eql_v3.query_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_date_ord_ope: eql_v3.query_date_ord_ope and public.eql_v3_date_ord (mismatched query domain).
--! @param a eql_v3.query_date_ord_ope left operand
--! @param b public.eql_v3_date_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_date_ord_ope, b public.eql_v3_date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'eql_v3.query_date_ord_ope and public.eql_v3_date_ord'; END; $$
LANGUAGE plpgsql;
