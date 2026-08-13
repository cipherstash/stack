-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_match_functions.sql

--! @file encrypted_domain/text/query_text_match_operators.sql
--! @brief Operators for eql_v3.query_text_match.

CREATE OPERATOR @@ (
  FUNCTION = eql_v3.matches,
  LEFTARG = public.eql_v3_text_match, RIGHTARG = eql_v3.query_text_match,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3.matches,
  LEFTARG = eql_v3.query_text_match, RIGHTARG = public.eql_v3_text_match,
  RESTRICT = contsel, JOIN = contjoinsel
);
