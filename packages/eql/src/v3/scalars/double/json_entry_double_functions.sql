-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/json/functions.sql
-- REQUIRE: src/v3/scalars/double/query_double_types.sql
-- REQUIRE: src/v3/scalars/double/query_double_ord_functions.sql
-- REQUIRE: src/v3/scalars/double/query_double_ord_ope_functions.sql

--! @file encrypted_domain/double/json_entry_double_functions.sql
--! @brief Functions for public.{{prefix}}_json_entry.

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_double_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_double_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_double_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_double_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_double_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_double_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_double_ord, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_double_ord, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_double_ord, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_double_ord, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_double_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_double_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_double_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_double_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_double_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_double_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord_ope
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_double_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord_ope
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_double_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord_ope
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_double_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a public.{{prefix}}_json_entry
--! @param b {{prefix}}.query_double_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_json_entry, b {{prefix}}.query_double_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_json_entry.
--! @param a {{prefix}}.query_double_ord_ope
--! @param b public.{{prefix}}_json_entry
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_double_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;
