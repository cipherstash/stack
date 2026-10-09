-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/smallint/smallint_types.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/hmac_256/functions.sql

--! @file encrypted_domain/smallint/smallint_eq_functions.sql
--! @brief Functions for public.{{prefix}}_smallint_eq.

--! @brief Index extractor for public.{{prefix}}_smallint_eq.
--! @param a public.{{prefix}}_smallint_eq
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a public.{{prefix}}_smallint_eq)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for public.{{prefix}}_smallint_eq.
--! @param a public.{{prefix}}_smallint_eq
--! @param b public.{{prefix}}_smallint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_smallint_eq.
--! @param a public.{{prefix}}_smallint_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b::public.{{prefix}}_smallint_eq) $$;

--! @brief Operator wrapper for public.{{prefix}}_smallint_eq.
--! @param a jsonb
--! @param b public.{{prefix}}_smallint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a::public.{{prefix}}_smallint_eq) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_smallint_eq.
--! @param a public.{{prefix}}_smallint_eq
--! @param b public.{{prefix}}_smallint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_smallint_eq.
--! @param a public.{{prefix}}_smallint_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b::public.{{prefix}}_smallint_eq) $$;

--! @brief Operator wrapper for public.{{prefix}}_smallint_eq.
--! @param a jsonb
--! @param b public.{{prefix}}_smallint_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a::public.{{prefix}}_smallint_eq) <> {{prefix}}.eq_term(b) $$;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lt(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.lte(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gt(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.gte(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.{{prefix}}_smallint_eq never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_smallint_eq, selector text)
RETURNS public.{{prefix}}_smallint_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.{{prefix}}_smallint_eq never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_smallint_eq, selector integer)
RETURNS public.{{prefix}}_smallint_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return public.{{prefix}}_smallint_eq never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a jsonb, selector public.{{prefix}}_smallint_eq)
RETURNS public.{{prefix}}_smallint_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_smallint_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_smallint_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a jsonb, selector public.{{prefix}}_smallint_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?"(a public.{{prefix}}_smallint_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?|"(a public.{{prefix}}_smallint_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?&"(a public.{{prefix}}_smallint_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@?"(a public.{{prefix}}_smallint_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_smallint_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>"(a public.{{prefix}}_smallint_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>>"(a public.{{prefix}}_smallint_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_smallint_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_smallint_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_smallint_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#-"(a public.{{prefix}}_smallint_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_smallint_eq, b public.{{prefix}}_smallint_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_smallint_eq left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_smallint_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_smallint_eq.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_smallint_eq and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_smallint_eq right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a jsonb, b public.{{prefix}}_smallint_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_smallint_eq'; END; $$
LANGUAGE plpgsql;
