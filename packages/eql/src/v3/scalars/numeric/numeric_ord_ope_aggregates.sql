-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/numeric/numeric_types.sql
-- REQUIRE: src/v3/scalars/numeric/numeric_ord_ope_functions.sql
-- REQUIRE: src/v3/scalars/numeric/numeric_ord_ope_operators.sql

--! @file encrypted_domain/numeric/numeric_ord_ope_aggregates.sql
--! @brief Aggregates for public.{{prefix}}_numeric_ord_ope.

--! @brief State function for min on public.{{prefix}}_numeric_ord_ope.
--! @param state public.{{prefix}}_numeric_ord_ope
--! @param value public.{{prefix}}_numeric_ord_ope
--! @return public.{{prefix}}_numeric_ord_ope
CREATE FUNCTION {{prefix}}_internal.min_sfunc(state public.{{prefix}}_numeric_ord_ope, value public.{{prefix}}_numeric_ord_ope)
RETURNS public.{{prefix}}_numeric_ord_ope
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

--! @brief min aggregate for public.{{prefix}}_numeric_ord_ope.
--! @param input public.{{prefix}}_numeric_ord_ope
--! @return public.{{prefix}}_numeric_ord_ope
CREATE AGGREGATE {{prefix}}.min(public.{{prefix}}_numeric_ord_ope) (
  sfunc = {{prefix}}_internal.min_sfunc,
  stype = public.{{prefix}}_numeric_ord_ope,
  combinefunc = {{prefix}}_internal.min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.{{prefix}}_numeric_ord_ope.
--! @param state public.{{prefix}}_numeric_ord_ope
--! @param value public.{{prefix}}_numeric_ord_ope
--! @return public.{{prefix}}_numeric_ord_ope
CREATE FUNCTION {{prefix}}_internal.max_sfunc(state public.{{prefix}}_numeric_ord_ope, value public.{{prefix}}_numeric_ord_ope)
RETURNS public.{{prefix}}_numeric_ord_ope
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

--! @brief max aggregate for public.{{prefix}}_numeric_ord_ope.
--! @param input public.{{prefix}}_numeric_ord_ope
--! @return public.{{prefix}}_numeric_ord_ope
CREATE AGGREGATE {{prefix}}.max(public.{{prefix}}_numeric_ord_ope) (
  sfunc = {{prefix}}_internal.max_sfunc,
  stype = public.{{prefix}}_numeric_ord_ope,
  combinefunc = {{prefix}}_internal.max_sfunc,
  parallel = safe
);
