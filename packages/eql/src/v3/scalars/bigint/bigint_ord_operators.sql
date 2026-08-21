-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_types.sql
-- REQUIRE: src/v3/scalars/bigint/bigint_ord_functions.sql

--! @file encrypted_domain/bigint/bigint_ord_operators.sql
--! @brief Operators for public.eql_v3_bigint_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3_internal.contains,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3_internal.contains,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3_internal.contains,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3_internal.contained_by,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3_internal.contained_by,
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3_internal.contained_by,
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3_internal."->",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3_internal."->",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3_internal."->",
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3_internal."->>",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3_internal."->>",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3_internal."->>",
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3_internal."?",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3_internal."?|",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3_internal."?&",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3_internal."@?",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal."@@",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3_internal."#>",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3_internal."#>>",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3_internal."-",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3_internal."-",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3_internal."-",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3_internal."#-",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3_internal."||",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = public.eql_v3_bigint_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3_internal."||",
  LEFTARG = public.eql_v3_bigint_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3_internal."||",
  LEFTARG = jsonb, RIGHTARG = public.eql_v3_bigint_ord
);
