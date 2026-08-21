-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_types.sql
-- REQUIRE: src/v3/scalars/timestamp/json_entry_timestamp_functions.sql

--! @file encrypted_domain/timestamp/json_entry_timestamp_operators.sql
--! @brief Operators for public.eql_v3_json_entry.

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_timestamp_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_timestamp_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = eql_v3.query_timestamp_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = eql_v3.query_timestamp_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = eql_v3.query_timestamp_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = eql_v3.query_timestamp_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_timestamp_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_timestamp_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord_ope
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = eql_v3.query_timestamp_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord_ope
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = eql_v3.query_timestamp_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord_ope
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = eql_v3.query_timestamp_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_timestamp_ord_ope
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = eql_v3.query_timestamp_ord_ope, RIGHTARG = public.eql_v3_json_entry
);
