-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/scalars/double/query_double_types.sql
-- REQUIRE: src/v3/scalars/double/json_entry_double_functions.sql

--! @file encrypted_domain/double/json_entry_double_operators.sql
--! @brief Operators for public.eql_v3_json_entry.

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_double_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_double_ord, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.query_double_ord, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.query_double_ord, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.query_double_ord, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.query_double_ord, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.eq,
  LEFTARG = eql_v3.query_double_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.neq,
  LEFTARG = eql_v3.query_double_ord_ope, RIGHTARG = public.eql_v3_json_entry
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord_ope,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.query_double_ord_ope, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord_ope,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.query_double_ord_ope, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord_ope,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.query_double_ord_ope, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_double_ord_ope,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.query_double_ord_ope, RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);
