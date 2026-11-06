-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_eq_functions.sql

--! @file encrypted_domain/text/query_text_eq_operators.sql
--! @brief Operators for eql_v3.query_text_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = public.eql_v3_text_eq, RIGHTARG = eql_v3.query_text_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = public.eql_v3_text_eq, RIGHTARG = eql_v3.query_text_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_search_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_search_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_eq
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_eq, RIGHTARG = public.eql_v3_text_search
);
