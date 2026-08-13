-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/query_bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_ord_ore_functions.sql

--! @file encrypted_domain/bigint/query_bigint_ord_ore_functions.sql
--! @brief Functions for eql_v3.query_bigint_ord_ore.

--! @brief Index extractor for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @return eql_v3_internal.ore_block_256
CREATE FUNCTION eql_v3.ord_term_ore(a eql_v3.query_bigint_ord_ore)
RETURNS eql_v3_internal.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3_internal.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a public.eql_v3_bigint_ord_ore
--! @param b eql_v3.query_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) = eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @param b public.eql_v3_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.query_bigint_ord_ore, b public.eql_v3_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) = eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a public.eql_v3_bigint_ord_ore
--! @param b eql_v3.query_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) <> eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @param b public.eql_v3_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.query_bigint_ord_ore, b public.eql_v3_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) <> eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a public.eql_v3_bigint_ord_ore
--! @param b eql_v3.query_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) < eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @param b public.eql_v3_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.query_bigint_ord_ore, b public.eql_v3_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) < eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a public.eql_v3_bigint_ord_ore
--! @param b eql_v3.query_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) <= eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @param b public.eql_v3_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.query_bigint_ord_ore, b public.eql_v3_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) <= eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a public.eql_v3_bigint_ord_ore
--! @param b eql_v3.query_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) > eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @param b public.eql_v3_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.query_bigint_ord_ore, b public.eql_v3_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) > eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a public.eql_v3_bigint_ord_ore
--! @param b eql_v3.query_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a public.eql_v3_bigint_ord_ore, b eql_v3.query_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) >= eql_v3.ord_term_ore(b) $$;

--! @brief Operator wrapper for eql_v3.query_bigint_ord_ore.
--! @param a eql_v3.query_bigint_ord_ore
--! @param b public.eql_v3_bigint_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.query_bigint_ord_ore, b public.eql_v3_bigint_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term_ore(a) >= eql_v3.ord_term_ore(b) $$;
