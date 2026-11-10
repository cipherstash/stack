-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_types.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_eq_functions.sql

--! @file encrypted_domain/numeric/query_numeric_eq_operators.sql
--! @brief Operators for {{prefix}}.query_numeric_eq.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_numeric_eq, RIGHTARG = {{prefix}}.query_numeric_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_numeric_eq, RIGHTARG = public.{{prefix}}_numeric_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_numeric_eq, RIGHTARG = {{prefix}}.query_numeric_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_numeric_eq, RIGHTARG = public.{{prefix}}_numeric_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);
