-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/hmac_256/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql
-- REQUIRE: src/v3/sem/bloom_filter/functions.sql

--! @file encrypted_domain/text/text_search_functions.sql
--! @brief Functions for public.eql_v3_text_search.

--! @brief Index extractor for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @return eql_v3_internal.hmac_256
CREATE FUNCTION eql_v3.eq_term(a public.eql_v3_text_search)
RETURNS eql_v3_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.hmac_256(a::jsonb) $$;

--! @brief Index extractor for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @return eql_v3_internal.ope_cllw
CREATE FUNCTION eql_v3.ord_term(a public.eql_v3_text_search)
RETURNS eql_v3_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.ope_cllw(a::jsonb) $$;

--! @brief Index extractor for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @return eql_v3_internal.bloom_filter
CREATE FUNCTION eql_v3.match_term(a public.eql_v3_text_search)
RETURNS eql_v3_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::public.eql_v3_text_search) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::public.eql_v3_text_search) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::public.eql_v3_text_search) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::public.eql_v3_text_search) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::public.eql_v3_text_search) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::public.eql_v3_text_search) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::public.eql_v3_text_search) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::public.eql_v3_text_search) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::public.eql_v3_text_search) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::public.eql_v3_text_search) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::public.eql_v3_text_search) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::public.eql_v3_text_search) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b public.eql_v3_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_text_search, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contains(a jsonb, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b public.eql_v3_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_text_search, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_search right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal.contained_by(a jsonb, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return public.eql_v3_text_search never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a public.eql_v3_text_search, selector text)
RETURNS public.eql_v3_text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return public.eql_v3_text_search never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a public.eql_v3_text_search, selector integer)
RETURNS public.eql_v3_text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.eql_v3_text_search right operand of the blocked operator
--! @return public.eql_v3_text_search never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->"(a jsonb, selector public.eql_v3_text_search)
RETURNS public.eql_v3_text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param selector text right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a public.eql_v3_text_search, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param selector integer right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a public.eql_v3_text_search, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param selector public.eql_v3_text_search right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."->>"(a jsonb, selector public.eql_v3_text_search)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?"(a public.eql_v3_text_search, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?|"(a public.eql_v3_text_search, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."?&"(a public.eql_v3_text_search, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@?"(a public.eql_v3_text_search, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a)) = 0) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a public.eql_v3_text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b::public.eql_v3_text_search) AND (cardinality(eql_v3.match_term(b::public.eql_v3_text_search)) > 0 OR cardinality(eql_v3.match_term(a)) = 0) $$;

--! @brief Operator wrapper for public.eql_v3_text_search.
--! @param a jsonb
--! @param b public.eql_v3_text_search
--! @return boolean
CREATE FUNCTION eql_v3.matches(a jsonb, b public.eql_v3_text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a::public.eql_v3_text_search) @> eql_v3.match_term(b) AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a::public.eql_v3_text_search)) = 0) $$;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b jsonpath right operand of the blocked operator
--! @return boolean never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_text_search, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#>"(a public.eql_v3_text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return text never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#>>"(a public.eql_v3_text_search, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_text_search, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b integer right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_text_search, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."-"(a public.eql_v3_text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b text[] right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."#-"(a public.eql_v3_text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b public.eql_v3_text_search right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a public.eql_v3_text_search, b public.eql_v3_text_search)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a public.eql_v3_text_search left operand of the blocked operator
--! @param b jsonb right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a public.eql_v3_text_search, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for public.eql_v3_text_search.
--!
--! Intercepts an operator that is not supported on public.eql_v3_text_search and always raises;
--! it never returns a value. The declared signature exists only so the operator
--! resolves to this blocker instead of a base-type fallback.
--!
--! @param a jsonb left operand of the blocked operator
--! @param b public.eql_v3_text_search right operand of the blocked operator
--! @return jsonb never returned — the function always raises "operator not supported"
CREATE FUNCTION eql_v3_internal."||"(a jsonb, b public.eql_v3_text_search)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;
