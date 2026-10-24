-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/json_tree/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql

--! @file v3/json_tree/operators.sql
--! @brief Operators on public.{{prefix}}_json_tree and public.{{prefix}}_json_tree_entry.

------------------------------------------------------------------------------
-- -> and ->> accessors (by selector)
------------------------------------------------------------------------------

--! @brief -> operator with a text selector: the first entry at the path.
--!
--! Returns the entry whose `s` equals @p selector, with the document's
--! `h`, `i`, `v` and the entry's ordinal `j` grafted on, so it opens on its
--! own. Inlinable: `{{prefix}}.ord_term(col -> 'sel')` matches a functional
--! btree on that expression.
--!
--! @warning The selector operand MUST carry a known type: a text-typed
--!   parameter or an explicit cast (`col -> 'sel'::text`). A bare untyped
--!   literal resolves to the NATIVE `jsonb -> text` operator and silently
--!   returns native jsonb semantics, as it does on every EQL jsonb domain.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param selector text The path selector, base64.
--! @return public.{{prefix}}_json_tree_entry The entry, or NULL.
CREATE FUNCTION {{prefix}}."->"(e public.{{prefix}}_json_tree, selector text)
  RETURNS public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_path_query_first(e::jsonb, selector)
$$;

CREATE OPERATOR ->(
  FUNCTION={{prefix}}."->",
  LEFTARG=public.{{prefix}}_json_tree,
  RIGHTARG=text
);

--! @brief ->> operator with a text selector: the first entry at the path, as
--!        JSON text. It does not decrypt.
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param selector text The path selector, base64.
--! @return text The entry as text, or NULL.
CREATE FUNCTION {{prefix}}."->>"(e public.{{prefix}}_json_tree, selector text)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION={{prefix}}."->>",
  LEFTARG=public.{{prefix}}_json_tree,
  RIGHTARG=text
);

------------------------------------------------------------------------------
-- @> and <@ containment
------------------------------------------------------------------------------

--! @brief @> contains operator with a query_json_tree needle.
--!
--! Inlines to native `jsonb @>` over `{{prefix}}.json_tree_query(a)`, so
--! a functional GIN index on that expression engages. Not STRICT, for the
--! reason `{{prefix}}.json_tree_contains` gives: a STRICT wrapper around a
--! non-STRICT body is not inlined.
--!
--! @param a public.{{prefix}}_json_tree The container.
--! @param b {{prefix}}.query_json_tree The needle.
--! @return boolean True when `a` contains `b`; NULL when either is NULL.
--! @see {{prefix}}.json_tree_contains
CREATE FUNCTION {{prefix}}."@>"(a public.{{prefix}}_json_tree, b {{prefix}}.query_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_contains(a, b)
$$;

CREATE OPERATOR @>(
  FUNCTION={{prefix}}."@>",
  LEFTARG=public.{{prefix}}_json_tree,
  RIGHTARG={{prefix}}.query_json_tree
);

--! @brief @> contains operator (document, document).
--! @param a public.{{prefix}}_json_tree The container.
--! @param b public.{{prefix}}_json_tree The contained document.
--! @return boolean True when `a` contains `b`.
CREATE FUNCTION {{prefix}}."@>"(a public.{{prefix}}_json_tree, b public.{{prefix}}_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_document_contains(a, b)
$$;

CREATE OPERATOR @>(
  FUNCTION={{prefix}}."@>",
  LEFTARG=public.{{prefix}}_json_tree,
  RIGHTARG=public.{{prefix}}_json_tree
);

--! @brief <@ contained-by operator with a query_json_tree container.
--! @param a public.{{prefix}}_json_tree The contained document.
--! @param b {{prefix}}.query_json_tree The needle that must contain it.
--! @return boolean True when `b` contains `a`.
--! @see {{prefix}}.json_tree_contained_by
CREATE FUNCTION {{prefix}}."<@"(a public.{{prefix}}_json_tree, b {{prefix}}.query_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_contained_by(a, b)
$$;

CREATE OPERATOR <@(
  FUNCTION={{prefix}}."<@",
  LEFTARG=public.{{prefix}}_json_tree,
  RIGHTARG={{prefix}}.query_json_tree
);

--! @brief <@ contained-by operator with a query_json_tree LHS: `b @> a`.
--! Not STRICT, as `@>` is not.
--! @param a {{prefix}}.query_json_tree The needle.
--! @param b public.{{prefix}}_json_tree The container.
--! @return boolean True when `b` contains `a`; NULL when either is NULL.
CREATE FUNCTION {{prefix}}."<@"(a {{prefix}}.query_json_tree, b public.{{prefix}}_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_contains(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION={{prefix}}."<@",
  LEFTARG={{prefix}}.query_json_tree,
  RIGHTARG=public.{{prefix}}_json_tree
);

--! @brief <@ contained-by operator (document, document).
--! @param a public.{{prefix}}_json_tree The contained document.
--! @param b public.{{prefix}}_json_tree The container.
--! @return boolean True when `b` contains `a`.
CREATE FUNCTION {{prefix}}."<@"(a public.{{prefix}}_json_tree, b public.{{prefix}}_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_document_contains(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION={{prefix}}."<@",
  LEFTARG=public.{{prefix}}_json_tree,
  RIGHTARG=public.{{prefix}}_json_tree
);

------------------------------------------------------------------------------
-- Ordering at a path: entry against an ordering operand
------------------------------------------------------------------------------

--! @brief Less-than on an extracted entry against an ordering operand, via
--!        the CLLW OPE term (native bytea order).
--! @param a public.{{prefix}}_json_tree_entry The entry, `col -> 'sel'`.
--! @param b {{prefix}}.query_json_tree_leaf The operand.
--! @return boolean True when the entry's leaf is below the operand's.
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_json_tree_entry, b {{prefix}}.query_json_tree_leaf)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = {{prefix}}.query_json_tree_leaf,
  NEGATOR  = >=,
  RESTRICT = scalarltsel,
  JOIN     = scalarltjoinsel
);

--! @brief Less-than-or-equal on an extracted entry against an ordering operand.
--! @param a public.{{prefix}}_json_tree_entry The entry.
--! @param b {{prefix}}.query_json_tree_leaf The operand.
--! @return boolean True when the entry's leaf is at or below the operand's.
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_json_tree_entry, b {{prefix}}.query_json_tree_leaf)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = {{prefix}}.query_json_tree_leaf,
  NEGATOR  = >,
  RESTRICT = scalarlesel,
  JOIN     = scalarlejoinsel
);

--! @brief Greater-than on an extracted entry against an ordering operand.
--! @param a public.{{prefix}}_json_tree_entry The entry.
--! @param b {{prefix}}.query_json_tree_leaf The operand.
--! @return boolean True when the entry's leaf is above the operand's.
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_json_tree_entry, b {{prefix}}.query_json_tree_leaf)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = {{prefix}}.query_json_tree_leaf,
  NEGATOR  = <=,
  RESTRICT = scalargtsel,
  JOIN     = scalargtjoinsel
);

--! @brief Greater-than-or-equal on an extracted entry against an ordering operand.
--! @param a public.{{prefix}}_json_tree_entry The entry.
--! @param b {{prefix}}.query_json_tree_leaf The operand.
--! @return boolean True when the entry's leaf is at or above the operand's.
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_json_tree_entry, b {{prefix}}.query_json_tree_leaf)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = {{prefix}}.query_json_tree_leaf,
  NEGATOR  = <,
  RESTRICT = scalargesel,
  JOIN     = scalargejoinsel
);

------------------------------------------------------------------------------
-- Ordering between two extracted entries
------------------------------------------------------------------------------

--! @brief Less-than between two extracted entries via their OPE terms.
--! @param a public.{{prefix}}_json_tree_entry Left operand.
--! @param b public.{{prefix}}_json_tree_entry Right operand.
--! @return boolean True when `a`'s leaf is below `b`'s.
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_json_tree_entry, b public.{{prefix}}_json_tree_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = public.{{prefix}}_json_tree_entry,
  COMMUTATOR = >,
  NEGATOR  = >=,
  RESTRICT = scalarltsel,
  JOIN     = scalarltjoinsel
);

--! @brief Less-than-or-equal between two extracted entries.
--! @param a public.{{prefix}}_json_tree_entry Left operand.
--! @param b public.{{prefix}}_json_tree_entry Right operand.
--! @return boolean True when `a`'s leaf is at or below `b`'s.
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_json_tree_entry, b public.{{prefix}}_json_tree_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = public.{{prefix}}_json_tree_entry,
  COMMUTATOR = >=,
  NEGATOR  = >,
  RESTRICT = scalarlesel,
  JOIN     = scalarlejoinsel
);

--! @brief Greater-than between two extracted entries.
--! @param a public.{{prefix}}_json_tree_entry Left operand.
--! @param b public.{{prefix}}_json_tree_entry Right operand.
--! @return boolean True when `a`'s leaf is above `b`'s.
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_json_tree_entry, b public.{{prefix}}_json_tree_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = public.{{prefix}}_json_tree_entry,
  COMMUTATOR = <,
  NEGATOR  = <=,
  RESTRICT = scalargtsel,
  JOIN     = scalargtjoinsel
);

--! @brief Greater-than-or-equal between two extracted entries.
--! @param a public.{{prefix}}_json_tree_entry Left operand.
--! @param b public.{{prefix}}_json_tree_entry Right operand.
--! @return boolean True when `a`'s leaf is at or above `b`'s.
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_json_tree_entry, b public.{{prefix}}_json_tree_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG  = public.{{prefix}}_json_tree_entry,
  RIGHTARG = public.{{prefix}}_json_tree_entry,
  COMMUTATOR = <=,
  NEGATOR  = <,
  RESTRICT = scalargesel,
  JOIN     = scalargejoinsel
);
