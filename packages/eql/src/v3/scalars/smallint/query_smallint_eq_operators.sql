-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/smallint/query_smallint_types.sql
-- REQUIRE: src/v3/scalars/smallint/query_smallint_eq_functions.sql

--! @file encrypted_domain/smallint/query_smallint_eq_operators.sql
--! @brief Operators for {{prefix}}.query_smallint_eq.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_smallint_eq, RIGHTARG = {{prefix}}.query_smallint_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_smallint_eq, RIGHTARG = public.{{prefix}}_smallint_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_smallint_eq, RIGHTARG = {{prefix}}.query_smallint_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_smallint_eq, RIGHTARG = public.{{prefix}}_smallint_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);
