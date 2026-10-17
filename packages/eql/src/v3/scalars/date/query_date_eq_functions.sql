-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/query_date_types.sql
-- REQUIRE: src/v3/scalars/date/date_eq_functions.sql

--! @file encrypted_domain/date/query_date_eq_functions.sql
--! @brief Functions for {{prefix}}.query_date_eq.

--! @brief Index extractor for {{prefix}}.query_date_eq.
--! @param a {{prefix}}.query_date_eq
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_date_eq)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a public.{{prefix}}_date_eq
--! @param b {{prefix}}.query_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_date_eq, b {{prefix}}.query_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a {{prefix}}.query_date_eq
--! @param b public.{{prefix}}_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a public.{{prefix}}_date_eq
--! @param b {{prefix}}.query_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_date_eq, b {{prefix}}.query_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_eq.
--! @param a {{prefix}}.query_date_eq
--! @param b public.{{prefix}}_date_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_date_eq, b public.{{prefix}}_date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;
