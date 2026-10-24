-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/text_types.sql
-- REQUIRE: src/v3/scalars/text/text_functions.sql

--! @file encrypted_domain/text/text_operators.sql
--! @brief Operators for public.{{prefix}}_text.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.contains,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.contains,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.contains,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.contained_by,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.contained_by,
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.contained_by,
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal."->",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal."->",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal."->",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal."->>",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal."->>",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal."->>",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR ? (
  FUNCTION = {{prefix}}_internal."?",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = {{prefix}}_internal."?|",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = {{prefix}}_internal."?&",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = {{prefix}}_internal."@?",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}_internal."@@",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}_internal."@@",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}_internal."@@",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}_internal."@@",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = {{prefix}}_internal."#>",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = {{prefix}}_internal."#>>",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal."-",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal."-",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal."-",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = {{prefix}}_internal."#-",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal."||",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = public.{{prefix}}_text
);

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal."||",
  LEFTARG = public.{{prefix}}_text, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal."||",
  LEFTARG = jsonb, RIGHTARG = public.{{prefix}}_text
);
