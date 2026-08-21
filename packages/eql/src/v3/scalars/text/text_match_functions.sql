-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/bloom_filter/functions.sql

--! @file encrypted_domain/text/text_match_functions.sql
--! @brief Functions for public.eql_v3_text_match.

--! @brief Index extractor for public.eql_v3_text_match.
--! @param a public.eql_v3_text_match
--! @return eql_v3_internal.bloom_filter
CREATE FUNCTION eql_v3.match_term(a public.eql_v3_text_match)
RETURNS eql_v3_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.bloom_filter(a::jsonb) $$;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.eq(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.neq(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lt(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.lte(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gt(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.gte(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a jsonb, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.eql_v3_text_match never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a public.eql_v3_text_match, selector text)
RETURNS public.eql_v3_text_match IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.eql_v3_text_match never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a public.eql_v3_text_match, selector integer)
RETURNS public.eql_v3_text_match IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.eql_v3_text_match right operand of the blocked operator
--! @return public.eql_v3_text_match never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a jsonb, selector public.eql_v3_text_match)
RETURNS public.eql_v3_text_match IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a public.eql_v3_text_match, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a public.eql_v3_text_match, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.eql_v3_text_match right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a jsonb, selector public.eql_v3_text_match)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?"(a public.eql_v3_text_match, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?|"(a public.eql_v3_text_match, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?&"(a public.eql_v3_text_match, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@?"(a public.eql_v3_text_match, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.eql_v3_text_match.
--! @param a public.eql_v3_text_match
--! @param b public.eql_v3_text_match
--! @return boolean
CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a)) = 0) $$;

--! @brief Operator wrapper for public.eql_v3_text_match.
--! @param a public.eql_v3_text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_match, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b::public.eql_v3_text_match) AND (cardinality(eql_v3.match_term(b::public.eql_v3_text_match)) > 0 OR cardinality(eql_v3.match_term(a)) = 0) $$;

--! @brief Operator wrapper for public.eql_v3_text_match.
--! @param a jsonb
--! @param b public.eql_v3_text_match
--! @return boolean
CREATE FUNCTION eql_v3.matches(a jsonb, b public.eql_v3_text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a::public.eql_v3_text_match) @> eql_v3.match_term(b) AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a::public.eql_v3_text_match)) = 0) $$;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_text_match, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#>"(a public.eql_v3_text_match, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#>>"(a public.eql_v3_text_match, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_text_match, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_text_match, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_text_match, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#-"(a public.eql_v3_text_match, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a public.eql_v3_text_match, b public.eql_v3_text_match)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_match left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a public.eql_v3_text_match, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_match.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_match and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_match right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a jsonb, b public.eql_v3_text_match)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;
