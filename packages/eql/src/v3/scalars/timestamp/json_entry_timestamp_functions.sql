-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/json/functions.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_types.sql

--! @file encrypted_domain/timestamp/json_entry_timestamp_functions.sql
--! @brief Functions for public.{{prefix}}_json_entry.

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_timestamp_ord, b public.{{prefix}}_json_entry)
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
--! @param b {{prefix}}.query_timestamp_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_timestamp_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_timestamp_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_timestamp_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_timestamp_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_timestamp_ord, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a {{prefix}}.query_timestamp_ord_ope, b public.{{prefix}}_json_entry)
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
--! @param b {{prefix}}.query_timestamp_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a {{prefix}}.query_timestamp_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a {{prefix}}.query_timestamp_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a {{prefix}}.query_timestamp_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a {{prefix}}.query_timestamp_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_json_entry left operand of the blocked operator
--! @param b {{prefix}}.query_timestamp_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_json_entry, b {{prefix}}.query_timestamp_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_json_entry.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_json_entry and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a {{prefix}}.query_timestamp_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_json_entry right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a {{prefix}}.query_timestamp_ord_ope, b public.{{prefix}}_json_entry)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_json_entry'; END; $$
LANGUAGE plpgsql;
