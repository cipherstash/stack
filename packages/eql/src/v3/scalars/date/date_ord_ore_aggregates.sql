-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/date_types.sql
-- REQUIRE: src/v3/scalars/date/date_ord_ore_functions.sql
-- REQUIRE: src/v3/scalars/date/date_ord_ore_operators.sql

--! @file encrypted_domain/date/date_ord_ore_aggregates.sql
--! @brief Aggregates for public.{{prefix}}_date_ord_ore.

--! @brief State function for min on public.{{prefix}}_date_ord_ore.
--! @param state public.{{prefix}}_date_ord_ore
--! @param value public.{{prefix}}_date_ord_ore
--! @return public.{{prefix}}_date_ord_ore
CREATE FUNCTION {{prefix}}_internal.min_sfunc(state public.{{prefix}}_date_ord_ore, value public.{{prefix}}_date_ord_ore)
RETURNS public.{{prefix}}_date_ord_ore
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

--! @brief min aggregate for public.{{prefix}}_date_ord_ore.
--! @param input public.{{prefix}}_date_ord_ore
--! @return public.{{prefix}}_date_ord_ore
CREATE AGGREGATE {{prefix}}.min(public.{{prefix}}_date_ord_ore) (
  sfunc = {{prefix}}_internal.min_sfunc,
  stype = public.{{prefix}}_date_ord_ore,
  combinefunc = {{prefix}}_internal.min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.{{prefix}}_date_ord_ore.
--! @param state public.{{prefix}}_date_ord_ore
--! @param value public.{{prefix}}_date_ord_ore
--! @return public.{{prefix}}_date_ord_ore
CREATE FUNCTION {{prefix}}_internal.max_sfunc(state public.{{prefix}}_date_ord_ore, value public.{{prefix}}_date_ord_ore)
RETURNS public.{{prefix}}_date_ord_ore
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

--! @brief max aggregate for public.{{prefix}}_date_ord_ore.
--! @param input public.{{prefix}}_date_ord_ore
--! @return public.{{prefix}}_date_ord_ore
CREATE AGGREGATE {{prefix}}.max(public.{{prefix}}_date_ord_ore) (
  sfunc = {{prefix}}_internal.max_sfunc,
  stype = public.{{prefix}}_date_ord_ore,
  combinefunc = {{prefix}}_internal.max_sfunc,
  parallel = safe
);
