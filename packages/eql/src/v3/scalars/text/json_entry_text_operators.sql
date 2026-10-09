-- AUTOMATICALLY GENERATED FILE.
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/scalars/text/query_text_types.sql
-- REQUIRE: src/v3/scalars/text/json_entry_text_functions.sql

--! @file encrypted_domain/text/json_entry_text_operators.sql
--! @brief Operators for public.{{prefix}}_json_entry.

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_text_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_text_ord, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = {{prefix}}.query_text_ord, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = {{prefix}}.query_text_ord, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = {{prefix}}.query_text_ord, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = {{prefix}}.query_text_ord, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord_ope
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_text_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord_ope
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_text_ord_ope, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord_ope,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG = {{prefix}}.query_text_ord_ope, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord_ope,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG = {{prefix}}.query_text_ord_ope, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord_ope,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG = {{prefix}}.query_text_ord_ope, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_ord_ope,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG = {{prefix}}.query_text_ord_ope, RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_search
);

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.eq,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_search
);

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.neq,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_search
);

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.lt,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_search
);

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.lte,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_search
);

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.gt,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_json_entry
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = public.{{prefix}}_json_entry, RIGHTARG = {{prefix}}.query_text_search
);

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.gte,
  LEFTARG = {{prefix}}.query_text_search, RIGHTARG = public.{{prefix}}_json_entry
);
