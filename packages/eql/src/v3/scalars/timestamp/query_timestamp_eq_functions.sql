-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_types.sql
-- REQUIRE: src/v3/scalars/timestamp/timestamp_eq_functions.sql

--! @file encrypted_domain/timestamp/query_timestamp_eq_functions.sql
--! @brief Functions for {{prefix}}.query_timestamp_eq.

--! @brief Index extractor for {{prefix}}.query_timestamp_eq.
--! @param a {{prefix}}.query_timestamp_eq
--! @return {{prefix}}_internal.hmac_256
CREATE FUNCTION {{prefix}}.eq_term(a {{prefix}}.query_timestamp_eq)
RETURNS {{prefix}}_internal.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_timestamp_eq.
--! @param a public.{{prefix}}_timestamp_eq
--! @param b {{prefix}}.query_timestamp_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_timestamp_eq, b {{prefix}}.query_timestamp_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_timestamp_eq.
--! @param a {{prefix}}.query_timestamp_eq
--! @param b public.{{prefix}}_timestamp_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_timestamp_eq, b public.{{prefix}}_timestamp_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) = {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_timestamp_eq.
--! @param a public.{{prefix}}_timestamp_eq
--! @param b {{prefix}}.query_timestamp_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_timestamp_eq, b {{prefix}}.query_timestamp_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_timestamp_eq.
--! @param a {{prefix}}.query_timestamp_eq
--! @param b public.{{prefix}}_timestamp_eq
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_timestamp_eq, b public.{{prefix}}_timestamp_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.eq_term(a) <> {{prefix}}.eq_term(b) $$;
