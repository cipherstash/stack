-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_ord_ope_functions.sql

--! @file encrypted_domain/text/query_text_ord_ope_functions.sql
--! @brief Functions for eql_v3.query_text_ord_ope.

--! @brief Index extractor for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @return eql_v3_internal.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.query_text_ord_ope)
RETURNS eql_v3_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.hmac_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @return eql_v3_internal.ope_cllw
CREATE FUNCTION eql_v3.ord_term(a eql_v3.query_text_ord_ope)
RETURNS eql_v3_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a public.eql_v3_text_ord_ope
--! @param b eql_v3.query_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_text_ord_ope, b eql_v3.query_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @param b public.eql_v3_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_text_ord_ope, b public.eql_v3_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a public.eql_v3_text_ord_ope
--! @param b eql_v3.query_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_text_ord_ope, b eql_v3.query_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @param b public.eql_v3_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_text_ord_ope, b public.eql_v3_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a public.eql_v3_text_ord_ope
--! @param b eql_v3.query_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_text_ord_ope, b eql_v3.query_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @param b public.eql_v3_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_text_ord_ope, b public.eql_v3_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a public.eql_v3_text_ord_ope
--! @param b eql_v3.query_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_text_ord_ope, b eql_v3.query_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @param b public.eql_v3_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_text_ord_ope, b public.eql_v3_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a public.eql_v3_text_ord_ope
--! @param b eql_v3.query_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_text_ord_ope, b eql_v3.query_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @param b public.eql_v3_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_text_ord_ope, b public.eql_v3_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a public.eql_v3_text_ord_ope
--! @param b eql_v3.query_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_text_ord_ope, b eql_v3.query_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.query_text_ord_ope.
--! @param a eql_v3.query_text_ord_ope
--! @param b public.eql_v3_text_ord_ope
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_text_ord_ope, b public.eql_v3_text_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;
