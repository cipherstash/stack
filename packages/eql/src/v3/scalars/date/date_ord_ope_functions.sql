-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/date_types.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql

--! @file encrypted_domain/date/date_ord_ope_functions.sql
--! @brief Functions for public.{{prefix}}_date_ord_ope.

--! @brief Index extractor for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @return {{prefix}}_internal.ope_cllw
CREATE FUNCTION {{prefix}}.ord_term(a public.{{prefix}}_date_ord_ope)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) = {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) = {{prefix}}.ord_term(b::public.{{prefix}}_date_ord_ope) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a jsonb
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_date_ord_ope) = {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <> {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <> {{prefix}}.ord_term(b::public.{{prefix}}_date_ord_ope) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a jsonb
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_date_ord_ope) <> {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b::public.{{prefix}}_date_ord_ope) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a jsonb
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_date_ord_ope) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b::public.{{prefix}}_date_ord_ope) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a jsonb
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_date_ord_ope) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b::public.{{prefix}}_date_ord_ope) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a jsonb
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_date_ord_ope) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a public.{{prefix}}_date_ord_ope
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b::public.{{prefix}}_date_ord_ope) $$;

--! @brief Operator wrapper for public.{{prefix}}_date_ord_ope.
--! @param a jsonb
--! @param b public.{{prefix}}_date_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_date_ord_ope) >= {{prefix}}.ord_term(b) $$;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.{{prefix}}_date_ord_ope never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_date_ord_ope, selector text)
RETURNS public.{{prefix}}_date_ord_ope IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.{{prefix}}_date_ord_ope never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_date_ord_ope, selector integer)
RETURNS public.{{prefix}}_date_ord_ope IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return public.{{prefix}}_date_ord_ope never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a jsonb, selector public.{{prefix}}_date_ord_ope)
RETURNS public.{{prefix}}_date_ord_ope IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_date_ord_ope, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_date_ord_ope, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a jsonb, selector public.{{prefix}}_date_ord_ope)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?"(a public.{{prefix}}_date_ord_ope, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?|"(a public.{{prefix}}_date_ord_ope, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?&"(a public.{{prefix}}_date_ord_ope, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@?"(a public.{{prefix}}_date_ord_ope, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_date_ord_ope, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>"(a public.{{prefix}}_date_ord_ope, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>>"(a public.{{prefix}}_date_ord_ope, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_date_ord_ope, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_date_ord_ope, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_date_ord_ope, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#-"(a public.{{prefix}}_date_ord_ope, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_date_ord_ope, b public.{{prefix}}_date_ord_ope)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_date_ord_ope left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_date_ord_ope, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_date_ord_ope.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_date_ord_ope and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_date_ord_ope right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a jsonb, b public.{{prefix}}_date_ord_ope)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_date_ord_ope'; END; $$
LANGUAGE plpgsql;
