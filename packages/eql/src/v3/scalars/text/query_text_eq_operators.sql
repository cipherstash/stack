-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_eq_functions.sql

--! @file encrypted_domain/text/query_text_eq_operators.sql
--! @brief Operators for {{prefix}}.query_text_eq.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_text_eq, RIGHTARG = {{prefix}}.query_text_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_text_eq, RIGHTARG = public.{{prefix}}_text_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_text_eq, RIGHTARG = {{prefix}}.query_text_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_text_eq, RIGHTARG = public.{{prefix}}_text_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);
