-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_search_functions.sql

--! @file encrypted_domain/text/query_text_search_operators.sql
--! @brief Operators for {{prefix}}.query_text_search.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = {{prefix}}.query_text_search,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_text_search,
  RESTRICT = contsel, JOIN = contjoinsel
);
