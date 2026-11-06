-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/smallint/query_smallint_types.sql
-- REQUIRE: src/v3/scalars/smallint/smallint_ord_functions.sql

--! @file encrypted_domain/smallint/query_smallint_ord_functions.sql
--! @brief Functions for eql_v3.query_smallint_ord.

--! @brief Index extractor for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @return eql_v3_internal.ope_cllw
CREATE FUNCTION eql_v3.ord_term(a eql_v3.query_smallint_ord)
RETURNS eql_v3_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a public.eql_v3_smallint_ord
--! @param b eql_v3.query_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_smallint_ord, b eql_v3.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @param b public.eql_v3_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a public.eql_v3_smallint_ord
--! @param b eql_v3.query_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_smallint_ord, b eql_v3.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @param b public.eql_v3_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a public.eql_v3_smallint_ord
--! @param b eql_v3.query_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_smallint_ord, b eql_v3.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @param b public.eql_v3_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a public.eql_v3_smallint_ord
--! @param b eql_v3.query_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_smallint_ord, b eql_v3.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @param b public.eql_v3_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a public.eql_v3_smallint_ord
--! @param b eql_v3.query_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_smallint_ord, b eql_v3.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @param b public.eql_v3_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a public.eql_v3_smallint_ord
--! @param b eql_v3.query_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_smallint_ord, b eql_v3.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_smallint_ord.
--! @param a eql_v3.query_smallint_ord
--! @param b public.eql_v3_smallint_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Blocker: public.eql_v3_smallint_eq = eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_eq left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_smallint_eq, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'public.eql_v3_smallint_eq', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord = public.eql_v3_smallint_eq always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_eq <> eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_eq left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_smallint_eq, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'public.eql_v3_smallint_eq', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord <> public.eql_v3_smallint_eq always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ore = eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ore left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_smallint_ord_ore, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'public.eql_v3_smallint_ord_ore', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord = public.eql_v3_smallint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ore <> eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ore left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_smallint_ord_ore, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'public.eql_v3_smallint_ord_ore', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord <> public.eql_v3_smallint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ore < eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ore left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_smallint_ord_ore, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<', 'public.eql_v3_smallint_ord_ore', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord < public.eql_v3_smallint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ore <= eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ore left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_smallint_ord_ore, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<=', 'public.eql_v3_smallint_ord_ore', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord <= public.eql_v3_smallint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ore > eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ore left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_smallint_ord_ore, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>', 'public.eql_v3_smallint_ord_ore', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord > public.eql_v3_smallint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ore >= eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ore left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_smallint_ord_ore, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>=', 'public.eql_v3_smallint_ord_ore', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord >= public.eql_v3_smallint_ord_ore always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ope = eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ope left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_smallint_ord_ope, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'public.eql_v3_smallint_ord_ope', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord = public.eql_v3_smallint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ope <> eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ope left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_smallint_ord_ope, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'public.eql_v3_smallint_ord_ope', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord <> public.eql_v3_smallint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<>', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ope < eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ope left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_smallint_ord_ope, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<', 'public.eql_v3_smallint_ord_ope', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord < public.eql_v3_smallint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ope <= eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ope left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_smallint_ord_ope, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<=', 'public.eql_v3_smallint_ord_ope', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord <= public.eql_v3_smallint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '<=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ope > eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ope left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_smallint_ord_ope, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>', 'public.eql_v3_smallint_ord_ope', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord > public.eql_v3_smallint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: public.eql_v3_smallint_ord_ope >= eql_v3.query_smallint_ord always raises (mismatched query domain).
--! @param a public.eql_v3_smallint_ord_ope left operand
--! @param b eql_v3.query_smallint_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_smallint_ord_ope, b eql_v3.query_smallint_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>=', 'public.eql_v3_smallint_ord_ope', 'eql_v3.query_smallint_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Blocker: eql_v3.query_smallint_ord >= public.eql_v3_smallint_ord_ope always raises (mismatched query domain).
--! @param a eql_v3.query_smallint_ord left operand
--! @param b public.eql_v3_smallint_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_smallint_ord, b public.eql_v3_smallint_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported between % and %: use the query domain that matches the column', '>=', 'eql_v3.query_smallint_ord', 'public.eql_v3_smallint_ord_ope'; END; $$
LANGUAGE plpgsql;
