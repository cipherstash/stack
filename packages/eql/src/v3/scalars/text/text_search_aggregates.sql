-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/text/text_search_functions.sql
-- REQUIRE: src/v3/scalars/text/text_search_operators.sql

--! @file encrypted_domain/text/text_search_aggregates.sql
--! @brief Aggregates for public.{{prefix}}_text_search.

--! @brief State function for min on public.{{prefix}}_text_search.
--! @param state public.{{prefix}}_text_search
--! @param value public.{{prefix}}_text_search
--! @return public.{{prefix}}_text_search
CREATE FUNCTION {{prefix}}_internal.min_sfunc(state public.{{prefix}}_text_search, value public.{{prefix}}_text_search)
RETURNS public.{{prefix}}_text_search
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

--! @brief min aggregate for public.{{prefix}}_text_search.
--! @param input public.{{prefix}}_text_search
--! @return public.{{prefix}}_text_search
CREATE AGGREGATE {{prefix}}.min(public.{{prefix}}_text_search) (
  sfunc = {{prefix}}_internal.min_sfunc,
  stype = public.{{prefix}}_text_search,
  combinefunc = {{prefix}}_internal.min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.{{prefix}}_text_search.
--! @param state public.{{prefix}}_text_search
--! @param value public.{{prefix}}_text_search
--! @return public.{{prefix}}_text_search
CREATE FUNCTION {{prefix}}_internal.max_sfunc(state public.{{prefix}}_text_search, value public.{{prefix}}_text_search)
RETURNS public.{{prefix}}_text_search
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

--! @brief max aggregate for public.{{prefix}}_text_search.
--! @param input public.{{prefix}}_text_search
--! @return public.{{prefix}}_text_search
CREATE AGGREGATE {{prefix}}.max(public.{{prefix}}_text_search) (
  sfunc = {{prefix}}_internal.max_sfunc,
  stype = public.{{prefix}}_text_search,
  combinefunc = {{prefix}}_internal.max_sfunc,
  parallel = safe
);
