-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_match_functions.sql

--! @file encrypted_domain/text/query_text_match_operators.sql
--! @brief Operators for {{prefix}}.query_text_match.

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = public.{{prefix}}_text_match, RIGHTARG = {{prefix}}.query_text_match,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}.matches,
  LEFTARG = {{prefix}}.query_text_match, RIGHTARG = public.{{prefix}}_text_match,
  RESTRICT = contsel, JOIN = contjoinsel
);
