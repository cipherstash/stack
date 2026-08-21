-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/query_bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/query_bigint_eq_functions.sql

--! @file encrypted_domain/bigint/query_bigint_eq_operators.sql
--! @brief Operators for eql_v3.query_bigint_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = public.eql_v3_bigint_eq, RIGHTARG = eql_v3.query_bigint_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.query_bigint_eq, RIGHTARG = public.eql_v3_bigint_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = public.eql_v3_bigint_eq, RIGHTARG = eql_v3.query_bigint_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.query_bigint_eq, RIGHTARG = public.eql_v3_bigint_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);
