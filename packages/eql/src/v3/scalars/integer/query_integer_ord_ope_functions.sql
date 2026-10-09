-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/integer/query_integer_types.sql
-- REQUIRE: src/v3/scalars/integer/integer_ord_ope_functions.sql

--! @file encrypted_domain/integer/query_integer_ord_ope_functions.sql
--! @brief Functions for {{prefix}}.query_integer_ord_ope.

--! @brief Index extractor for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @return {{prefix}}_internal.ope_cllw
CREATE FUNCTION {{prefix}}.ord_term(a {{prefix}}.query_integer_ord_ope)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a public.{{prefix}}_integer_ord_ope
--! @param b {{prefix}}.query_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_integer_ord_ope, b {{prefix}}.query_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) = {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @param b public.{{prefix}}_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_integer_ord_ope, b public.{{prefix}}_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) = {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a public.{{prefix}}_integer_ord_ope
--! @param b {{prefix}}.query_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_integer_ord_ope, b {{prefix}}.query_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <> {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @param b public.{{prefix}}_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_integer_ord_ope, b public.{{prefix}}_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <> {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a public.{{prefix}}_integer_ord_ope
--! @param b {{prefix}}.query_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_integer_ord_ope, b {{prefix}}.query_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @param b public.{{prefix}}_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_integer_ord_ope, b public.{{prefix}}_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a public.{{prefix}}_integer_ord_ope
--! @param b {{prefix}}.query_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_integer_ord_ope, b {{prefix}}.query_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @param b public.{{prefix}}_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_integer_ord_ope, b public.{{prefix}}_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a public.{{prefix}}_integer_ord_ope
--! @param b {{prefix}}.query_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_integer_ord_ope, b {{prefix}}.query_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @param b public.{{prefix}}_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_integer_ord_ope, b public.{{prefix}}_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a public.{{prefix}}_integer_ord_ope
--! @param b {{prefix}}.query_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_integer_ord_ope, b {{prefix}}.query_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_integer_ord_ope.
--! @param a {{prefix}}.query_integer_ord_ope
--! @param b public.{{prefix}}_integer_ord_ope
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_integer_ord_ope, b public.{{prefix}}_integer_ord_ope)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;
