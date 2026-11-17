-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/query_text_search_ore_functions.sql

--! @file encrypted_domain/text/query_text_search_ore_operators.sql
--! @brief Operators for eql_v3.query_text_search_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3.matches,
  LEFTARG = public.eql_v3_text_search_ore, RIGHTARG = eql_v3.query_text_search_ore,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3.matches,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search_ore,
  RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_eq, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_eq
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_eq, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_eq
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = public.eql_v3_text_match, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_match
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = public.eql_v3_text_ord_ore, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = public.eql_v3_text_ord, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = public.eql_v3_text_ord_ope, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.lt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.lte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.gt,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.gte,
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = public.eql_v3_text_search, RIGHTARG = eql_v3.query_text_search_ore
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = eql_v3.query_text_search_ore, RIGHTARG = public.eql_v3_text_search
);
