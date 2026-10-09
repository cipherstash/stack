-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/json/functions.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql

--! @file v3/json/operators.sql
--! @brief Operators on public.{{prefix}}_json_search and public.{{prefix}}_json_entry.

------------------------------------------------------------------------------
-- -> field accessor (returns jsonb_entry)
------------------------------------------------------------------------------

--! @brief -> operator with text selector.
--!
--! Returns the sv entry whose `s` equals @p selector, with root `i`/`v` merged
--! in. Inlinable: range predicates reduce structurally through
--! `{{prefix}}.ord_term(col -> 'sel')` and match a functional btree index on that
--! expression. Exact equality is document containment on a value selector.
--!
--! @warning The selector operand MUST carry a known type — a text-typed
--!   parameter (`$1`, the Proxy interface) or an explicit cast (`col -> 'sel'::%text`).
--!   A bare untyped literal (`col -> 'sel'`) resolves to the NATIVE `jsonb -> %text`
--!   operator and silently returns native jsonb semantics (a root-key lookup,
--!   typically NULL), NOT this operator: PostgreSQL reduces the `public.{{prefix}}_json_search`
--!   domain to its base type `jsonb` when resolving an unknown-typed RHS, and the
--!   native base-type operator wins the exact-match tiebreak. This is intrinsic to
--!   the domain type-kind and applies to the native-jsonb blockers too. See
--!   the "Typed operands" caveat in docs/reference/json-support.md.
--!
--! @param e public.{{prefix}}_json_search Root encrypted payload.
--! @param selector text Selector hash.
--! @return public.{{prefix}}_json_entry Matching entry merged with root meta, or NULL.
CREATE FUNCTION {{prefix}}."->"(e public.{{prefix}}_json_search, selector text)
  RETURNS public.{{prefix}}_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (
    {{prefix}}.meta_data(e) ||
    jsonb_path_query_first(
      e,
      '$.sv[*] ? (@.s == $sel)'::jsonpath,
      jsonb_build_object('sel', selector)
    )
  )::public.{{prefix}}_json_entry
$$;

CREATE OPERATOR ->(
  FUNCTION={{prefix}}."->",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG=text
);

--! @brief -> operator with integer array index (0-based, JSONB convention).
--! @param e public.{{prefix}}_json_search Encrypted sv-array payload.
--! @param selector integer Array index.
--! @return public.{{prefix}}_json_entry Matching entry merged with root meta, or NULL.
CREATE FUNCTION {{prefix}}."->"(e public.{{prefix}}_json_search, selector integer)
  RETURNS public.{{prefix}}_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN {{prefix}}_internal.is_ste_vec_array(e) THEN
      -- NOTE: `e::jsonb` makes the native-jsonb traversal explicit. `'sv'` is an
      -- unknown-typed literal, so `e -> 'sv'` already flattens `public.{{prefix}}_json_search` to
      -- its base type and binds native `jsonb -> text` (see the @warning above) —
      -- the custom `->(public.{{prefix}}_json_search, text)` operator does NOT capture a bare
      -- untyped literal. The cast documents that intent and guards the `-> selector`
      -- (integer) hop from ever resolving to the v3 `->(public.{{prefix}}_json_search, integer)`
      -- operator instead of native array access.
      ({{prefix}}.meta_data(e) || (e::jsonb -> 'sv' -> selector))::public.{{prefix}}_json_entry
    ELSE NULL
  END
$$;

CREATE OPERATOR ->(
  FUNCTION={{prefix}}."->",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG=integer
);

------------------------------------------------------------------------------
-- ->> field accessor (alias of -> coerced to text)
------------------------------------------------------------------------------

--! @brief ->> operator with text selector. Inlinable alias of -> coerced to
--!        text.
--!
--! Intentional v2 parity: this serializes the entire matched jsonb_entry
--! object as JSON text. It does not decrypt or return scalar plaintext like
--! native `jsonb ->>`.
--! @param e public.{{prefix}}_json_search Encrypted payload.
--! @param selector text Field selector hash.
--! @return text The matching entry as text.
CREATE FUNCTION {{prefix}}."->>"(e public.{{prefix}}_json_search, selector text)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION={{prefix}}."->>",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG=text
);

--! @brief ->> operator with integer array index. Inlinable alias of
--!        ->(json, integer) coerced to text.
--! @param e public.{{prefix}}_json_search Encrypted sv-array payload.
--! @param selector integer Array index.
--! @return text The matching entry as text.
CREATE FUNCTION {{prefix}}."->>"(e public.{{prefix}}_json_search, selector integer)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION={{prefix}}."->>",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG=integer
);

------------------------------------------------------------------------------
-- @> containment
------------------------------------------------------------------------------

--! @brief @> contains operator (document, document).
--! @param a public.{{prefix}}_json_search Container.
--! @param b public.{{prefix}}_json_search Contained value.
--! @return boolean True if a contains b.
--! @see {{prefix}}.jsonb_document_contains
CREATE FUNCTION {{prefix}}."@>"(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.jsonb_document_contains(a, b)
$$;

CREATE OPERATOR @>(
  FUNCTION={{prefix}}."@>",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG=public.{{prefix}}_json_search
);

--! @brief @> contains operator with an query_json needle.
--!
--! Inlines to native `jsonb @>` over `{{prefix}}.to_ste_vec_query(a)::jsonb`, so a
--! functional GIN index on the same expression engages.
--!
--! @param a public.{{prefix}}_json_search Container.
--! @param b {{prefix}}.query_json Query payload.
--! @return boolean True if a contains b.
CREATE FUNCTION {{prefix}}."@>"(a public.{{prefix}}_json_search, b {{prefix}}.query_json)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.to_ste_vec_query(a)::jsonb
       @> {{prefix}}.to_ste_vec_query(b)::jsonb
$$;

CREATE OPERATOR @>(
  FUNCTION={{prefix}}."@>",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG={{prefix}}.query_json
);

-- NOTE: there is deliberately NO computable `@>`(json_search, json_entry)
-- single-entry containment operator. `blockers.sql` claims the signature and
-- raises rather than allowing native-jsonb fallback. An extracted `json_entry` is a PATH entry
-- ({s,c,op?}) and carries no value selector, so it can only ever match
-- structurally ("the document has a node at this path") — value-blind for
-- bool/null/object/array and op-lossy for number/string. Exact field equality is
-- document containment on the value selector: `col @> $1::{{prefix}}.query_json`,
-- where a value-selector's presence in the stored document IS the exact match.
-- Routing all value equality through that one exact mechanism is why the
-- structural single-entry behavior (and its `<@` reverse) was blocked.

------------------------------------------------------------------------------
-- <@ contained-by (reverse of @>)
------------------------------------------------------------------------------

--! @brief <@ contained-by operator (document, document).
--! @param a public.{{prefix}}_json_search Contained value.
--! @param b public.{{prefix}}_json_search Container.
--! @return boolean True if a is contained by b.
CREATE FUNCTION {{prefix}}."<@"(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.to_ste_vec_query(b)::jsonb
       @> {{prefix}}.to_ste_vec_query(a)::jsonb
$$;

CREATE OPERATOR <@(
  FUNCTION={{prefix}}."<@",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG=public.{{prefix}}_json_search
);

--! @brief <@ contained-by operator with an query_json LHS.
--! @param a {{prefix}}.query_json Query payload.
--! @param b public.{{prefix}}_json_search Container.
--! @return boolean True if b contains a.
CREATE FUNCTION {{prefix}}."<@"(a {{prefix}}.query_json, b public.{{prefix}}_json_search)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}."@>"(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION={{prefix}}."<@",
  LEFTARG={{prefix}}.query_json,
  RIGHTARG=public.{{prefix}}_json_search
);

-- NOTE: `<@`(json_entry, json_search) is likewise a fail-loud blocker — it is
-- the reverse of the blocked single-entry `@>` behavior. See the note above.

------------------------------------------------------------------------------
-- jsonb_entry comparisons
------------------------------------------------------------------------------

--! @brief Block equality between two extracted jsonb entries.
--! @note An extracted entry is a path entry and carries no value selector.
--!       Comparing its deterministic `op` bytes would be lossy for
--!       `bigint`/`numeric`/`text`; exact equality is document containment on a
--!       value-selector needle. This blocker is deliberately non-STRICT so a
--!       NULL operand cannot bypass the error.
--! @param a public.{{prefix}}_json_entry Left operand
--! @param b public.{{prefix}}_json_entry Right operand
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}.eq(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
  RETURNS boolean
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}.eq,
  LEFTARG  = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Block inequality between two extracted jsonb entries.
--! @param a public.{{prefix}}_json_entry Left operand
--! @param b public.{{prefix}}_json_entry Right operand
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}.neq(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
  RETURNS boolean
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}.neq,
  LEFTARG  = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Less-than on jsonb_entry via the CLLW OPE term (native bytea order).
--! @param a public.{{prefix}}_json_entry Left operand
--! @param b public.{{prefix}}_json_entry Right operand
--! @return boolean True if a is less than b
CREATE FUNCTION {{prefix}}.lt(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) < {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}.lt,
  LEFTARG  = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = >,
  NEGATOR  = >=,
  RESTRICT = scalarltsel,
  JOIN     = scalarltjoinsel
);

--! @brief Less-than-or-equal on jsonb_entry via the CLLW OPE term.
--! @param a public.{{prefix}}_json_entry Left operand
--! @param b public.{{prefix}}_json_entry Right operand
--! @return boolean True if a is less than or equal to b
CREATE FUNCTION {{prefix}}.lte(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) <= {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}.lte,
  LEFTARG  = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = >=,
  NEGATOR  = >,
  RESTRICT = scalarlesel,
  JOIN     = scalarlejoinsel
);

--! @brief Greater-than on jsonb_entry via the CLLW OPE term.
--! @param a public.{{prefix}}_json_entry Left operand
--! @param b public.{{prefix}}_json_entry Right operand
--! @return boolean True if a is greater than b
CREATE FUNCTION {{prefix}}.gt(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) > {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}.gt,
  LEFTARG  = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = <,
  NEGATOR  = <=,
  RESTRICT = scalargtsel,
  JOIN     = scalargtjoinsel
);

--! @brief Greater-than-or-equal on jsonb_entry via the CLLW OPE term.
--! @param a public.{{prefix}}_json_entry Left operand
--! @param b public.{{prefix}}_json_entry Right operand
--! @return boolean True if a is greater than or equal to b
CREATE FUNCTION {{prefix}}.gte(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.ord_term(a) >= {{prefix}}.ord_term(b)
$$;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}.gte,
  LEFTARG  = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry,
  COMMUTATOR = <=,
  NEGATOR  = <,
  RESTRICT = scalargesel,
  JOIN     = scalargejoinsel
);
