-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/query_date_types.sql
-- REQUIRE: src/v3/scalars/date/date_ord_ore_functions.sql

--! @file encrypted_domain/date/query_date_ord_ore_functions.sql
--! @brief Functions for {{prefix}}.query_date_ord_ore.

--! @brief Index extractor for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @return {{prefix}}_internal.ore_block_256
CREATE FUNCTION {{prefix}}.ord_term_ore(a {{prefix}}.query_date_ord_ore)
RETURNS {{prefix}}_internal.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a public.{{prefix}}_date_ord_ore
--! @param b {{prefix}}.query_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) = {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @param b public.{{prefix}}_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.eq(a {{prefix}}.query_date_ord_ore, b public.{{prefix}}_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) = {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a public.{{prefix}}_date_ord_ore
--! @param b {{prefix}}.query_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) <> {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @param b public.{{prefix}}_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.neq(a {{prefix}}.query_date_ord_ore, b public.{{prefix}}_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) <> {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a public.{{prefix}}_date_ord_ore
--! @param b {{prefix}}.query_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) < {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @param b public.{{prefix}}_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lt(a {{prefix}}.query_date_ord_ore, b public.{{prefix}}_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) < {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a public.{{prefix}}_date_ord_ore
--! @param b {{prefix}}.query_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) <= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @param b public.{{prefix}}_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.lte(a {{prefix}}.query_date_ord_ore, b public.{{prefix}}_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) <= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a public.{{prefix}}_date_ord_ore
--! @param b {{prefix}}.query_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) > {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @param b public.{{prefix}}_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gt(a {{prefix}}.query_date_ord_ore, b public.{{prefix}}_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) > {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a public.{{prefix}}_date_ord_ore
--! @param b {{prefix}}.query_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_date_ord_ore, b {{prefix}}.query_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) >= {{prefix}}.ord_term_ore(b) $$;

--! @brief Operator wrapper for {{prefix}}.query_date_ord_ore.
--! @param a {{prefix}}.query_date_ord_ore
--! @param b public.{{prefix}}_date_ord_ore
--! @return boolean
CREATE FUNCTION {{prefix}}.gte(a {{prefix}}.query_date_ord_ore, b public.{{prefix}}_date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) >= {{prefix}}.ord_term_ore(b) $$;
