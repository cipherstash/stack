-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/smallint/query_smallint_types.sql
-- REQUIRE: src/v3/scalars/smallint/smallint_ord_functions.sql

--! @file encrypted_domain/smallint/query_smallint_ord_functions.sql
--! @brief Functions for {{prefix}}.query_smallint_ord.

--! @brief Index extractor for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @return {{prefix}}_internal.ope_cllw
CREATE FUNCTION {{prefix}}.ord_term(a {{prefix}}.query_smallint_ord)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a public.{{prefix}}_smallint_ord
--! @param b {{prefix}}.query_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_smallint_ord, b {{prefix}}.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) = {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @param b public.{{prefix}}_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_smallint_ord, b public.{{prefix}}_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) = {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a public.{{prefix}}_smallint_ord
--! @param b {{prefix}}.query_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_smallint_ord, b {{prefix}}.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <> {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @param b public.{{prefix}}_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_smallint_ord, b public.{{prefix}}_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <> {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a public.{{prefix}}_smallint_ord
--! @param b {{prefix}}.query_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_smallint_ord, b {{prefix}}.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @param b public.{{prefix}}_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_smallint_ord, b public.{{prefix}}_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a public.{{prefix}}_smallint_ord
--! @param b {{prefix}}.query_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_smallint_ord, b {{prefix}}.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @param b public.{{prefix}}_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_smallint_ord, b public.{{prefix}}_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a public.{{prefix}}_smallint_ord
--! @param b {{prefix}}.query_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_smallint_ord, b {{prefix}}.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @param b public.{{prefix}}_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_smallint_ord, b public.{{prefix}}_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a public.{{prefix}}_smallint_ord
--! @param b {{prefix}}.query_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_smallint_ord, b {{prefix}}.query_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_smallint_ord.
--! @param a {{prefix}}.query_smallint_ord
--! @param b public.{{prefix}}_smallint_ord
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_smallint_ord, b public.{{prefix}}_smallint_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b) $$;
