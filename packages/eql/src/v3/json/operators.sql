-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/json/functions.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql

--! @file v3/json/operators.sql
--! @brief Operators on public.eql_v3_json_search and public.eql_v3_json_entry.

------------------------------------------------------------------------------
-- -> field accessor (returns jsonb_entry)
------------------------------------------------------------------------------

--! @brief -> operator with text selector.
--!
--! Returns the sv entry whose `s` equals @p selector, with root `i`/`v` merged
--! in. Inlinable: range predicates reduce structurally through
--! `eql_v3.ord_term(col -> 'sel')` and match a functional btree index on that
--! expression. Exact equality is document containment on a value selector.
--!
--! @warning The selector operand MUST carry a known type — a text-typed
--!   parameter (`$1`, the Proxy interface) or an explicit cast (`col -> 'sel'::%text`).
--!   A bare untyped literal (`col -> 'sel'`) resolves to the NATIVE `jsonb -> %text`
--!   operator and silently returns native jsonb semantics (a root-key lookup,
--!   typically NULL), NOT this operator: PostgreSQL reduces the `public.eql_v3_json_search`
--!   domain to its base type `jsonb` when resolving an unknown-typed RHS, and the
--!   native base-type operator wins the exact-match tiebreak. This is intrinsic to
--!   the domain type-kind and applies to the native-jsonb blockers too. See
--!   the "Typed operands" caveat in docs/reference/json-support.md.
--!
--! @param e public.eql_v3_json_search Root encrypted payload.
--! @param selector text Selector hash.
--! @return public.eql_v3_json_entry Matching entry merged with root meta, or NULL.
CREATE FUNCTION eql_v3."->"(e public.eql_v3_json_search, selector text)
  RETURNS public.eql_v3_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (
    eql_v3.meta_data(e) ||
    jsonb_path_query_first(
      e,
      '$.sv[*] ? (@.s == $sel)'::jsonpath,
      jsonb_build_object('sel', selector)
    )
  )::public.eql_v3_json_entry
$$;

CREATE OPERATOR ->(
  FUNCTION=eql_v3."->",
  LEFTARG=public.eql_v3_json_search,
  RIGHTARG=text
);

--! @brief -> operator with integer array index (0-based, JSONB convention).
--! @param e public.eql_v3_json_search Encrypted sv-array payload.
--! @param selector integer Array index.
--! @return public.eql_v3_json_entry Matching entry merged with root meta, or NULL.
CREATE FUNCTION eql_v3."->"(e public.eql_v3_json_search, selector integer)
  RETURNS public.eql_v3_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN eql_v3_internal.is_ste_vec_array(e) THEN
      -- NOTE: `e::jsonb` makes the native-jsonb traversal explicit. `'sv'` is an
      -- unknown-typed literal, so `e -> 'sv'` already flattens `public.eql_v3_json_search` to
      -- its base type and binds native `jsonb -> text` (see the @warning above) —
      -- the custom `->(public.eql_v3_json_search, text)` operator does NOT capture a bare
      -- untyped literal. The cast documents that intent and guards the `-> selector`
      -- (integer) hop from ever resolving to the v3 `->(public.eql_v3_json_search, integer)`
      -- operator instead of native array access.
      (eql_v3.meta_data(e) || (e::jsonb -> 'sv' -> selector))::public.eql_v3_json_entry
    ELSE NULL
  END
$$;

CREATE OPERATOR ->(
  FUNCTION=eql_v3."->",
  LEFTARG=public.eql_v3_json_search,
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
--! @param e public.eql_v3_json_search Encrypted payload.
--! @param selector text Field selector hash.
--! @return text The matching entry as text.
CREATE FUNCTION eql_v3."->>"(e public.eql_v3_json_search, selector text)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION=eql_v3."->>",
  LEFTARG=public.eql_v3_json_search,
  RIGHTARG=text
);

--! @brief ->> operator with integer array index. Inlinable alias of
--!        ->(json, integer) coerced to text.
--! @param e public.eql_v3_json_search Encrypted sv-array payload.
--! @param selector integer Array index.
--! @return text The matching entry as text.
CREATE FUNCTION eql_v3."->>"(e public.eql_v3_json_search, selector integer)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION=eql_v3."->>",
  LEFTARG=public.eql_v3_json_search,
  RIGHTARG=integer
);

------------------------------------------------------------------------------
-- @> containment
------------------------------------------------------------------------------

--! @brief @> contains operator (document, document).
--! @param a public.eql_v3_json_search Container.
--! @param b public.eql_v3_json_search Contained value.
--! @return boolean True if a contains b.
--! @see eql_v3.jsonb_document_contains
CREATE FUNCTION eql_v3."@>"(a public.eql_v3_json_search, b public.eql_v3_json_search)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.jsonb_document_contains(a, b)
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v3."@>",
  LEFTARG=public.eql_v3_json_search,
  RIGHTARG=public.eql_v3_json_search
);

--! @brief @> contains operator with an query_json needle.
--!
--! Inlines to native `jsonb @>` over `eql_v3.to_ste_vec_query(a)::jsonb`, so a
--! functional GIN index on the same expression engages.
--!
--! @param a public.eql_v3_json_search Container.
--! @param b eql_v3.query_json Query payload.
--! @return boolean True if a contains b.
CREATE FUNCTION eql_v3."@>"(a public.eql_v3_json_search, b eql_v3.query_json)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.to_ste_vec_query(a)::jsonb
       @> eql_v3.to_ste_vec_query(b)::jsonb
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v3."@>",
  LEFTARG=public.eql_v3_json_search,
  RIGHTARG=eql_v3.query_json
);

-- NOTE: there is deliberately NO computable `@>`(json_search, json_entry)
-- single-entry containment operator. `blockers.sql` claims the signature and
-- raises rather than allowing native-jsonb fallback. An extracted `json_entry` is a PATH entry
-- ({s,c,op?}) and carries no value selector, so it can only ever match
-- structurally ("the document has a node at this path") — value-blind for
-- bool/null/object/array and op-lossy for number/string. Exact field equality is
-- document containment on the value selector: `col @> $1::eql_v3.query_json`,
-- where a value-selector's presence in the stored document IS the exact match.
-- Routing all value equality through that one exact mechanism is why the
-- structural single-entry behavior (and its `<@` reverse) was blocked.

------------------------------------------------------------------------------
-- <@ contained-by (reverse of @>)
------------------------------------------------------------------------------

--! @brief <@ contained-by operator (document, document).
--! @param a public.eql_v3_json_search Contained value.
--! @param b public.eql_v3_json_search Container.
--! @return boolean True if a is contained by b.
CREATE FUNCTION eql_v3."<@"(a public.eql_v3_json_search, b public.eql_v3_json_search)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.to_ste_vec_query(b)::jsonb
       @> eql_v3.to_ste_vec_query(a)::jsonb
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v3."<@",
  LEFTARG=public.eql_v3_json_search,
  RIGHTARG=public.eql_v3_json_search
);

--! @brief <@ contained-by operator with an query_json LHS.
--! @param a eql_v3.query_json Query payload.
--! @param b public.eql_v3_json_search Container.
--! @return boolean True if b contains a.
CREATE FUNCTION eql_v3."<@"(a eql_v3.query_json, b public.eql_v3_json_search)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."@>"(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v3."<@",
  LEFTARG=eql_v3.query_json,
  RIGHTARG=public.eql_v3_json_search
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
--! @param a public.eql_v3_json_entry Left operand
--! @param b public.eql_v3_json_entry Right operand
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.eq(a public.eql_v3_json_entry, b public.eql_v3_json_entry)
  RETURNS boolean
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_entry', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG  = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_entry
);

--! @brief Block inequality between two extracted jsonb entries.
--! @param a public.eql_v3_json_entry Left operand
--! @param b public.eql_v3_json_entry Right operand
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.neq(a public.eql_v3_json_entry, b public.eql_v3_json_entry)
  RETURNS boolean
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_entry', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG  = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_entry
);

--! @brief Less-than on jsonb_entry via the CLLW OPE term (native bytea order).
--! @param a public.eql_v3_json_entry Left operand
--! @param b public.eql_v3_json_entry Right operand
--! @return boolean True if a is less than b
CREATE FUNCTION eql_v3.lt(a public.eql_v3_json_entry, b public.eql_v3_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b)
$$;

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG  = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = >,
  NEGATOR  = >=,
  RESTRICT = scalarltsel,
  JOIN     = scalarltjoinsel
);

--! @brief Less-than-or-equal on jsonb_entry via the CLLW OPE term.
--! @param a public.eql_v3_json_entry Left operand
--! @param b public.eql_v3_json_entry Right operand
--! @return boolean True if a is less than or equal to b
CREATE FUNCTION eql_v3.lte(a public.eql_v3_json_entry, b public.eql_v3_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b)
$$;

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG  = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = >=,
  NEGATOR  = >,
  RESTRICT = scalarlesel,
  JOIN     = scalarlejoinsel
);

--! @brief Greater-than on jsonb_entry via the CLLW OPE term.
--! @param a public.eql_v3_json_entry Left operand
--! @param b public.eql_v3_json_entry Right operand
--! @return boolean True if a is greater than b
CREATE FUNCTION eql_v3.gt(a public.eql_v3_json_entry, b public.eql_v3_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b)
$$;

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG  = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = <,
  NEGATOR  = <=,
  RESTRICT = scalargtsel,
  JOIN     = scalargtjoinsel
);

--! @brief Greater-than-or-equal on jsonb_entry via the CLLW OPE term.
--! @param a public.eql_v3_json_entry Left operand
--! @param b public.eql_v3_json_entry Right operand
--! @return boolean True if a is greater than or equal to b
CREATE FUNCTION eql_v3.gte(a public.eql_v3_json_entry, b public.eql_v3_json_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b)
$$;

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG  = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_entry,
  COMMUTATOR = <=,
  NEGATOR  = <,
  RESTRICT = scalargesel,
  JOIN     = scalargejoinsel
);
