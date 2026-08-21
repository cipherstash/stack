-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/text/text_ord_functions.sql
-- REQUIRE: src/v3/scalars/text/text_ord_operators.sql

--! @file encrypted_domain/text/text_ord_aggregates.sql
--! @brief Aggregates for public.eql_v3_text_ord.

--! @brief State function for min on public.eql_v3_text_ord.
--! @param state public.eql_v3_text_ord
--! @param value public.eql_v3_text_ord
--! @return public.eql_v3_text_ord
CREATE FUNCTION eql_v3_internal.min_sfunc(state public.eql_v3_text_ord, value public.eql_v3_text_ord)
RETURNS public.eql_v3_text_ord
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

--! @brief min aggregate for public.eql_v3_text_ord.
--! @param input public.eql_v3_text_ord
--! @return public.eql_v3_text_ord
CREATE AGGREGATE eql_v3.min(public.eql_v3_text_ord) (
  sfunc = eql_v3_internal.min_sfunc,
  stype = public.eql_v3_text_ord,
  combinefunc = eql_v3_internal.min_sfunc,
  parallel = safe
);

--! @brief State function for max on public.eql_v3_text_ord.
--! @param state public.eql_v3_text_ord
--! @param value public.eql_v3_text_ord
--! @return public.eql_v3_text_ord
CREATE FUNCTION eql_v3_internal.max_sfunc(state public.eql_v3_text_ord, value public.eql_v3_text_ord)
RETURNS public.eql_v3_text_ord
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

--! @brief max aggregate for public.eql_v3_text_ord.
--! @param input public.eql_v3_text_ord
--! @return public.eql_v3_text_ord
CREATE AGGREGATE eql_v3.max(public.eql_v3_text_ord) (
  sfunc = eql_v3_internal.max_sfunc,
  stype = public.eql_v3_text_ord,
  combinefunc = eql_v3_internal.max_sfunc,
  parallel = safe
);
