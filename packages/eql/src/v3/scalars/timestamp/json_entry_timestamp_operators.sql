-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_types.sql
-- REQUIRE: src/v3/scalars/timestamp/json_entry_timestamp_functions.sql

--! @file encrypted_domain/timestamp/json_entry_timestamp_operators.sql
--! @brief Operators for public.{{prefix}}_json_entry.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_timestamp_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_timestamp_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_timestamp_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_timestamp_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_timestamp_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_timestamp_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_timestamp_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_timestamp_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord_ope
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_timestamp_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord_ope
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_timestamp_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord_ope
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_timestamp_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_timestamp_ord_ope
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_timestamp_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);
