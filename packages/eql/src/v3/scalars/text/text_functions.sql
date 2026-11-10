-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/functions.sql

--! @file encrypted_domain/text/text_functions.sql
--! @brief Functions for public.{{prefix}}_text.

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.eq(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.neq(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.{{prefix}}_text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_text, selector text)
RETURNS public.{{prefix}}_text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.{{prefix}}_text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_text, selector integer)
RETURNS public.{{prefix}}_text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_text right operand of the blocked operator
--! @return public.{{prefix}}_text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a jsonb, selector public.{{prefix}}_text)
RETURNS public.{{prefix}}_text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_text, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_text, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a jsonb, selector public.{{prefix}}_text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?"(a public.{{prefix}}_text, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?|"(a public.{{prefix}}_text, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?&"(a public.{{prefix}}_text, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@?"(a public.{{prefix}}_text, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a jsonb, b public.{{prefix}}_text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>"(a public.{{prefix}}_text, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>>"(a public.{{prefix}}_text, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_text, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_text, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_text, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#-"(a public.{{prefix}}_text, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_text, b public.{{prefix}}_text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_text, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a jsonb, b public.{{prefix}}_text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_text'; END; $$
LANGUAGE plpgsql;
