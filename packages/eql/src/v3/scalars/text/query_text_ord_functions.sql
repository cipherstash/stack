-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/text_ord_functions.sql

--! @file encrypted_domain/text/query_text_ord_functions.sql
--! @brief Functions for {{prefix}}.query_text_ord.

--! @brief Index extractor for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_text_ord)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Index extractor for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @return {{prefix}}_internal.ope_cllw
CREATE FUNCTION {{prefix}}.ord_term(a {{prefix}}.query_text_ord)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a public.{{prefix}}_text_ord
--! @param b {{prefix}}.query_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @param b public.{{prefix}}_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_text_ord, b public.{{prefix}}_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a public.{{prefix}}_text_ord
--! @param b {{prefix}}.query_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @param b public.{{prefix}}_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_text_ord, b public.{{prefix}}_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a public.{{prefix}}_text_ord
--! @param b {{prefix}}.query_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @param b public.{{prefix}}_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_text_ord, b public.{{prefix}}_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a public.{{prefix}}_text_ord
--! @param b {{prefix}}.query_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @param b public.{{prefix}}_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_text_ord, b public.{{prefix}}_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a public.{{prefix}}_text_ord
--! @param b {{prefix}}.query_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @param b public.{{prefix}}_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_text_ord, b public.{{prefix}}_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a public.{{prefix}}_text_ord
--! @param b {{prefix}}.query_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_text_ord, b {{prefix}}.query_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_text_ord.
--! @param a {{prefix}}.query_text_ord
--! @param b public.{{prefix}}_text_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_text_ord, b public.{{prefix}}_text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;
