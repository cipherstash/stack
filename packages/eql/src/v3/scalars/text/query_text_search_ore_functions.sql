-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_search_ore_functions.sql

--! @file encrypted_domain/text/query_text_search_ore_functions.sql
--! @brief Functions for eql_v3.query_text_search_ore.

--! @brief Index extractor for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @return eql_v3_internal.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.query_text_search_ore)
RETURNS eql_v3_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.hmac_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @return eql_v3_internal.ore_block_256
CREATE FUNCTION eql_v3.ord_term_ore(a eql_v3.query_text_search_ore)
RETURNS eql_v3_internal.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.ore_block_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @return eql_v3_internal.bloom_filter
CREATE FUNCTION eql_v3.match_term(a eql_v3.query_text_search_ore)
RETURNS eql_v3_internal.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) OPERATOR(pg_catalog.=) eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) OPERATOR(pg_catalog.=) eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) OPERATOR(pg_catalog.<>) eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) OPERATOR(pg_catalog.<>) eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.<) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.<) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.<=) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.<=) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.>) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.>) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.>=) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) OPERATOR(public.>=) eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a public.eql_v3_text_search_ore
--! @param b eql_v3.query_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_search_ore, b eql_v3.query_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) OPERATOR(pg_catalog.@>) eql_v3.match_term(b) AND (pg_catalog.cardinality(eql_v3.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality(eql_v3.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Operator wrapper for eql_v3.query_text_search_ore.
--! @param a eql_v3.query_text_search_ore
--! @param b public.eql_v3_text_search_ore
--! @return boolean
CREATE FUNCTION eql_v3.matches(a eql_v3.query_text_search_ore, b public.eql_v3_text_search_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) OPERATOR(pg_catalog.@>) eql_v3.match_term(b) AND (pg_catalog.cardinality(eql_v3.match_term(b)) OPERATOR(pg_catalog.>) 0 OR pg_catalog.cardinality(eql_v3.match_term(a)) OPERATOR(pg_catalog.=) 0) $$;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_eq and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_eq left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_eq, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_text_eq and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_eq (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_text_search_ore, b public.eql_v3_text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_text_search_ore and public.eql_v3_text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_eq and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_eq left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_eq, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_text_eq and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_eq (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_eq right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_text_search_ore, b public.eql_v3_text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_text_search_ore and public.eql_v3_text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_match and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_match left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_text_match, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.eql_v3_text_match and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_match (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_match right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a eql_v3.query_text_search_ore, b public.eql_v3_text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'eql_v3.query_text_search_ore and public.eql_v3_text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ore left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_ord_ore, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ore left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_ord_ore, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ore left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_text_ord_ore, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ore left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_text_ord_ore, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ore left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_text_ord_ore, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ore left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_text_ord_ore, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.eql_v3_text_ord_ore and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_ord, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_text_ord and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_ord, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_text_ord and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_text_ord, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.eql_v3_text_ord and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_text_ord, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.eql_v3_text_ord and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_text_ord, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.eql_v3_text_ord and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_text_ord, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.eql_v3_text_ord and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ope left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_ord_ope, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ope left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_ord_ope, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ope left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_text_ord_ope, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ope left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_text_ord_ope, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ope left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_text_ord_ope, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_ord_ope left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_text_ord_ope, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.eql_v3_text_ord_ope and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_ord_ope right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_text_search_ore, b public.eql_v3_text_ord_ope)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'eql_v3.query_text_search_ore and public.eql_v3_text_ord_ope'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '=', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.neq(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<>', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.lte(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '<=', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gt(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal.gte(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '>=', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: public.eql_v3_text_search and eql_v3.query_text_search_ore (mismatched query domain).
--! @param a public.eql_v3_text_search left operand
--! @param b eql_v3.query_text_search_ore right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a public.eql_v3_text_search, b eql_v3.query_text_search_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'public.eql_v3_text_search and eql_v3.query_text_search_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.query_text_search_ore: eql_v3.query_text_search_ore and public.eql_v3_text_search (mismatched query domain).
--! @param a eql_v3.query_text_search_ore left operand
--! @param b public.eql_v3_text_search right operand
--! @return boolean never returned — the function always raises
CREATE FUNCTION eql_v3_internal."@@"(a eql_v3.query_text_search_ore, b public.eql_v3_text_search)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %: use the query domain that matches the column', '@@', 'eql_v3.query_text_search_ore and public.eql_v3_text_search'; END; $$
LANGUAGE plpgsql;
