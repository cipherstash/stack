-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_types.sql
-- REQUIRE: src/v3/scalars/functions.sql

--! @file encrypted_domain/bigint/bigint_functions.sql
--! @brief Functions for public.eql_v3_bigint.

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lt(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lte(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gt(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gte(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.eql_v3_bigint never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a public.eql_v3_bigint, selector text)
RETURNS public.eql_v3_bigint IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.eql_v3_bigint never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a public.eql_v3_bigint, selector integer)
RETURNS public.eql_v3_bigint IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.eql_v3_bigint right operand of the blocked operator
--! @return public.eql_v3_bigint never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a jsonb, selector public.eql_v3_bigint)
RETURNS public.eql_v3_bigint IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a public.eql_v3_bigint, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a public.eql_v3_bigint, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.eql_v3_bigint right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a jsonb, selector public.eql_v3_bigint)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?"(a public.eql_v3_bigint, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?|"(a public.eql_v3_bigint, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?&"(a public.eql_v3_bigint, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@?"(a public.eql_v3_bigint, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_bigint, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@@"(a jsonb, b public.eql_v3_bigint)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_bigint, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#>"(a public.eql_v3_bigint, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#>>"(a public.eql_v3_bigint, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_bigint, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_bigint, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_bigint, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#-"(a public.eql_v3_bigint, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a public.eql_v3_bigint, b public.eql_v3_bigint)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_bigint left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a public.eql_v3_bigint, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_bigint.
--!
--! Intercepts an operator that is not supported on public.eql_v3_bigint and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_bigint right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a jsonb, b public.eql_v3_bigint)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_bigint'; END; $$
LANGUAGE plpgsql;
