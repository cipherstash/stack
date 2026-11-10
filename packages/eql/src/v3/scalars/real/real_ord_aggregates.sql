-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/real/real_types.sql
-- REQUIRE: src/v3/scalars/real/real_ord_functions.sql
-- REQUIRE: src/v3/scalars/real/real_ord_operators.sql

--! @file encrypted_domain/real/real_ord_aggregates.sql
--! @brief Aggregates for public.{{prefix}}_real_ord.

--! @brief State function for min on public.{{prefix}}_real_ord.
--! @param state public.{{prefix}}_real_ord
--! @param value public.{{prefix}}_real_ord
--! @return public.{{prefix}}_real_ord
CREATE FUNCTION {{prefix}}_internal.min_sfunc(state public.{{prefix}}_real_ord, value public.{{prefix}}_real_ord)
RETURNS public.{{prefix}}_real_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for public.{{prefix}}_real_ord.
--! @param input public.{{prefix}}_real_ord
--! @return public.{{prefix}}_real_ord
CREATE AGGREGATE {{prefix}}.min(public.{{prefix}}_real_ord) (
  sfunc = {{prefix}}_internal.min_sfunc,
  stype = public.{{prefix}}_real_ord,
  combinefunc = {{prefix}}_internal.min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.{{prefix}}_real_ord.
--! @param state public.{{prefix}}_real_ord
--! @param value public.{{prefix}}_real_ord
--! @return public.{{prefix}}_real_ord
CREATE FUNCTION {{prefix}}_internal.max_sfunc(state public.{{prefix}}_real_ord, value public.{{prefix}}_real_ord)
RETURNS public.{{prefix}}_real_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for public.{{prefix}}_real_ord.
--! @param input public.{{prefix}}_real_ord
--! @return public.{{prefix}}_real_ord
CREATE AGGREGATE {{prefix}}.max(public.{{prefix}}_real_ord) (
  sfunc = {{prefix}}_internal.max_sfunc,
  stype = public.{{prefix}}_real_ord,
  combinefunc = {{prefix}}_internal.max_sfunc,
  parallel = safe
);
