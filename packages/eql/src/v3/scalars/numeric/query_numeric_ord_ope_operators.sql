-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_types.sql
-- REQUIRE: src/v3/scalars/numeric/query_numeric_ord_ope_functions.sql

--! @file encrypted_domain/numeric/query_numeric_ord_ope_operators.sql
--! @brief Operators for {{prefix}}.query_numeric_ord_ope.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_numeric_ord_ope, RIGHTARG = {{prefix}}.query_numeric_ord_ope,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ope,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_numeric_ord_ope, RIGHTARG = {{prefix}}.query_numeric_ord_ope,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ope,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_numeric_ord_ope, RIGHTARG = {{prefix}}.query_numeric_ord_ope,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ope,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_numeric_ord_ope, RIGHTARG = {{prefix}}.query_numeric_ord_ope,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ope,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_numeric_ord_ope, RIGHTARG = {{prefix}}.query_numeric_ord_ope,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ope,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_numeric_ord_ope, RIGHTARG = {{prefix}}.query_numeric_ord_ope,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ope,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_numeric_eq, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_eq
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_numeric_eq, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_eq
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_numeric_ord_ore, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_numeric_ord_ore, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ore
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_numeric_ord_ore, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ore
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_numeric_ord_ore, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ore
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_numeric_ord_ore, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ore
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_numeric_ord_ore, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_numeric_ord, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_numeric_ord, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_numeric_ord, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_numeric_ord, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_numeric_ord, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_numeric_ord, RIGHTARG = {{prefix}}.query_numeric_ord_ope
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_numeric_ord_ope, RIGHTARG = public.{{prefix}}_numeric_ord
);
