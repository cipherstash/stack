-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_types.sql
-- REQUIRE: src/v3/scalars/timestamp/query_timestamp_eq_functions.sql

--! @file encrypted_domain/timestamp/query_timestamp_eq_operators.sql
--! @brief Operators for {{prefix}}.query_timestamp_eq.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_timestamp_eq, RIGHTARG = {{prefix}}.query_timestamp_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_timestamp_eq, RIGHTARG = {{prefix}}.query_timestamp_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_timestamp_ord_ore, RIGHTARG = {{prefix}}.query_timestamp_eq
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_timestamp_ord_ore, RIGHTARG = {{prefix}}.query_timestamp_eq
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_timestamp_ord, RIGHTARG = {{prefix}}.query_timestamp_eq
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_ord
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_timestamp_ord, RIGHTARG = {{prefix}}.query_timestamp_eq
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_ord
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_timestamp_ord_ope, RIGHTARG = {{prefix}}.query_timestamp_eq
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_timestamp_ord_ope, RIGHTARG = {{prefix}}.query_timestamp_eq
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_timestamp_eq, RIGHTARG = public.{{prefix}}_timestamp_ord_ope
);
