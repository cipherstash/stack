-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/hmac_256/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql
-- REQUIRE: src/v3/sem/bloom_filter/functions.sql

--! @file encrypted_domain/text/text_search_functions.sql
--! @brief Functions for public.{{prefix}}_text_search.

--! @brief Index extractor for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a public.{{prefix}}_text_search)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Index extractor for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @return {{prefix}}_internal.ope_cllw
CREATE FUNCTION {{prefix}}.ord_term(a public.{{prefix}}_text_search)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(a::jsonb) $$;

--! @brief Index extractor for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @return {{prefix}}_internal.bloom_filter
CREATE FUNCTION {{prefix}}.match_term(a public.{{prefix}}_text_search)
RETURNS {{prefix}}_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b::public.{{prefix}}_text_search) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a::public.{{prefix}}_text_search) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b::public.{{prefix}}_text_search) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a::public.{{prefix}}_text_search) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b::public.{{prefix}}_text_search) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_text_search) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b::public.{{prefix}}_text_search) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_text_search) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b::public.{{prefix}}_text_search) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_text_search) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b::public.{{prefix}}_text_search) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a::public.{{prefix}}_text_search) >= {{prefix}}.ord_term(b) $$;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b public.{{prefix}}_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contains(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b public.{{prefix}}_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal.contained_by(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.{{prefix}}_text_search never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_text_search, selector text)
RETURNS public.{{prefix}}_text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.{{prefix}}_text_search never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a public.{{prefix}}_text_search, selector integer)
RETURNS public.{{prefix}}_text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_text_search right operand of the blocked operator
--! @return public.{{prefix}}_text_search never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->"(a jsonb, selector public.{{prefix}}_text_search)
RETURNS public.{{prefix}}_text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_text_search, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a public.{{prefix}}_text_search, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.{{prefix}}_text_search right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."->>"(a jsonb, selector public.{{prefix}}_text_search)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?"(a public.{{prefix}}_text_search, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?|"(a public.{{prefix}}_text_search, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."?&"(a public.{{prefix}}_text_search, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@?"(a public.{{prefix}}_text_search, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a public.{{prefix}}_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a public.{{prefix}}_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a) @> {{prefix}}.match_term(b::public.{{prefix}}_text_search) AND (cardinality({{prefix}}.match_term(b::public.{{prefix}}_text_search)) > 0 OR cardinality({{prefix}}.match_term(a)) = 0) $$;

--! @brief Operator wrapper for public.{{prefix}}_text_search.
--! @param a jsonb
--! @param b public.{{prefix}}_text_search
--! @return boolean
CREATE FUNCTION {{prefix}}.matches(a jsonb, b public.{{prefix}}_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.match_term(a::public.{{prefix}}_text_search) @> {{prefix}}.match_term(b) AND (cardinality({{prefix}}.match_term(b)) > 0 OR cardinality({{prefix}}.match_term(a::public.{{prefix}}_text_search)) = 0) $$;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."@@"(a public.{{prefix}}_text_search, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>"(a public.{{prefix}}_text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#>>"(a public.{{prefix}}_text_search, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_text_search, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_text_search, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."-"(a public.{{prefix}}_text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."#-"(a public.{{prefix}}_text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b public.{{prefix}}_text_search right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_text_search, b public.{{prefix}}_text_search)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.{{prefix}}_text_search left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a public.{{prefix}}_text_search, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.{{prefix}}_text_search.
--!
--! Intercepts an operator that is not supported on public.{{prefix}}_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.{{prefix}}_text_search right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION {{prefix}}_internal."||"(a jsonb, b public.{{prefix}}_text_search)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.{{prefix}}_text_search'; END; $$
LANGUAGE plpgsql;
