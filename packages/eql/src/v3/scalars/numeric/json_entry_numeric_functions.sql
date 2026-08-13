-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/json/functions.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_types.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_ord_functions.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_ord_ope_functions.sql

--! @file encrypted_domain/numeric/json_entry_numeric_functions.sql
--! @brief Functions for public.eql_v3_json_entry.

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_json_entry left operand of the blocked operator
--! @param b eql_v3.query_numeric_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a eql_v3.query_numeric_ord left operand of the blocked operator
--! @param b public.eql_v3_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_numeric_ord, b public.eql_v3_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_json_entry left operand of the blocked operator
--! @param b eql_v3.query_numeric_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a eql_v3.query_numeric_ord left operand of the blocked operator
--! @param b public.eql_v3_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_numeric_ord, b public.eql_v3_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_numeric_ord, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_numeric_ord, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_numeric_ord, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_numeric_ord, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_json_entry left operand of the blocked operator
--! @param b eql_v3.query_numeric_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a eql_v3.query_numeric_ord_ope left operand of the blocked operator
--! @param b public.eql_v3_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_numeric_ord_ope, b public.eql_v3_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_json_entry left operand of the blocked operator
--! @param b eql_v3.query_numeric_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_json_entry.
--!
--! Intercepts an operator that is not supported on public.eql_v3_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a eql_v3.query_numeric_ord_ope left operand of the blocked operator
--! @param b public.eql_v3_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_numeric_ord_ope, b public.eql_v3_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord_ope
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_numeric_ord_ope, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord_ope
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_numeric_ord_ope, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord_ope
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_numeric_ord_ope, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a public.eql_v3_json_entry
--! @param b eql_v3.query_numeric_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_json_entry, b eql_v3.query_numeric_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_json_entry.
--! @param a eql_v3.query_numeric_ord_ope
--! @param b public.eql_v3_json_entry
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_numeric_ord_ope, b public.eql_v3_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;
