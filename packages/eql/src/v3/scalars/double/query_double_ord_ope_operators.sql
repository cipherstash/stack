-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/double/query_double_types.sql
-- REQUIRE: src/v3/scalars/double/query_double_ord_ope_functions.sql

--! @file encrypted_domain/double/query_double_ord_ope_operators.sql
--! @brief Operators for {{prefix}}.query_double_ord_ope.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ope,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_double_ord_ope, RIGHTARG = public.{{prefix}}_double_ord_ope,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ope,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_double_ord_ope, RIGHTARG = public.{{prefix}}_double_ord_ope,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ope,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = {{prefix}}.query_double_ord_ope, RIGHTARG = public.{{prefix}}_double_ord_ope,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ope,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = {{prefix}}.query_double_ord_ope, RIGHTARG = public.{{prefix}}_double_ord_ope,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ope,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = {{prefix}}.query_double_ord_ope, RIGHTARG = public.{{prefix}}_double_ord_ope,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ope,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = {{prefix}}.query_double_ord_ope, RIGHTARG = public.{{prefix}}_double_ord_ope,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);
