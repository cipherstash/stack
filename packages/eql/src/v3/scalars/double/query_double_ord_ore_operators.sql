-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/double/query_double_types.sql
-- REQUIRE: src/v3/scalars/double/query_double_ord_ore_functions.sql

--! @file encrypted_domain/double/query_double_ord_ore_operators.sql
--! @brief Operators for {{prefix}}.query_double_ord_ore.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_double_ord_ore, RIGHTARG = {{prefix}}.query_double_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_double_ord_ore, RIGHTARG = {{prefix}}.query_double_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_double_ord_ore, RIGHTARG = {{prefix}}.query_double_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_double_ord_ore, RIGHTARG = {{prefix}}.query_double_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_double_ord_ore, RIGHTARG = {{prefix}}.query_double_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_double_ord_ore, RIGHTARG = {{prefix}}.query_double_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_double_eq, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_eq
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_double_eq, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_eq
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_double_ord, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_double_ord, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_double_ord, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_double_ord, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_double_ord, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_double_ord, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ope
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ope
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ope
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ope
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_double_ord_ope, RIGHTARG = {{prefix}}.query_double_ord_ore
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_double_ord_ore, RIGHTARG = public.{{prefix}}_double_ord_ope
);
