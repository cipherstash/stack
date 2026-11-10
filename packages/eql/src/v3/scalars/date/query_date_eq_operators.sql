-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/date/query_date_types.sql
-- REQUIRE: src/v3/scalars/date/query_date_eq_functions.sql

--! @file encrypted_domain/date/query_date_eq_operators.sql
--! @brief Operators for {{prefix}}.query_date_eq.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_date_eq, RIGHTARG = {{prefix}}.query_date_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_date_eq, RIGHTARG = public.{{prefix}}_date_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_date_eq, RIGHTARG = {{prefix}}.query_date_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_date_eq, RIGHTARG = public.{{prefix}}_date_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);
