-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/text/text_search_functions.sql

--! @file encrypted_domain/text/text_search_operators.sql
--! @brief Operators for public.{{prefix}}_text_search.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.contains,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.contains,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.contains,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.contained_by,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.contained_by,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.contained_by,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal."->",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal."->",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal."->",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal."->>",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal."->>",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal."->>",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR ? (
  FUNCTION = {{prefix}}_internal."?",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = {{prefix}}_internal."?|",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = {{prefix}}_internal."?&",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = {{prefix}}_internal."@?",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}_internal."@@",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = {{prefix}}_internal."#>",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = {{prefix}}_internal."#>>",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal."-",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal."-",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal."-",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = {{prefix}}_internal."#-",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal."||",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = public.{{prefix}}_text_search
);

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal."||",
  LEFTARG = public.{{prefix}}_text_search, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal."||",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text_search
);
