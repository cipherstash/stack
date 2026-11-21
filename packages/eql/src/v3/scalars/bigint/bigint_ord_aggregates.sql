-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_ord_functions.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_ord_operators.sql

--! @file encrypted_domain/bigint/bigint_ord_aggregates.sql
--! @brief Aggregates for public.{{prefix}}_bigint_ord.

--! @brief State function for min on public.{{prefix}}_bigint_ord.
--! @param state public.{{prefix}}_bigint_ord
--! @param value public.{{prefix}}_bigint_ord
--! @return public.{{prefix}}_bigint_ord
CREATE FUNCTION {{prefix}}_internal.min_sfunc(state public.{{prefix}}_bigint_ord, value public.{{prefix}}_bigint_ord)
RETURNS public.{{prefix}}_bigint_ord
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

--! @brief min aggregate for public.{{prefix}}_bigint_ord.
--! @param input public.{{prefix}}_bigint_ord
--! @return public.{{prefix}}_bigint_ord
CREATE AGGREGATE {{prefix}}.min(public.{{prefix}}_bigint_ord) (
  sfunc = {{prefix}}_internal.min_sfunc,
  stype = public.{{prefix}}_bigint_ord,
  combinefunc = {{prefix}}_internal.min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.{{prefix}}_bigint_ord.
--! @param state public.{{prefix}}_bigint_ord
--! @param value public.{{prefix}}_bigint_ord
--! @return public.{{prefix}}_bigint_ord
CREATE FUNCTION {{prefix}}_internal.max_sfunc(state public.{{prefix}}_bigint_ord, value public.{{prefix}}_bigint_ord)
RETURNS public.{{prefix}}_bigint_ord
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

--! @brief max aggregate for public.{{prefix}}_bigint_ord.
--! @param input public.{{prefix}}_bigint_ord
--! @return public.{{prefix}}_bigint_ord
CREATE AGGREGATE {{prefix}}.max(public.{{prefix}}_bigint_ord) (
  sfunc = {{prefix}}_internal.max_sfunc,
  stype = public.{{prefix}}_bigint_ord,
  combinefunc = {{prefix}}_internal.max_sfunc,
  parallel = safe
);
