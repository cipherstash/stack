-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/json_tree/functions.sql
-- REQUIRE: src/v3/json_tree/operators.sql

--! @file v3/json_tree/elements.sql
--! @brief Element-scoped predicates on public.{{prefix}}_json_search: tests
--!        that one element of an array satisfies them all.

--! @brief Whether an entry is inside every bound of an ordering at one
--!        path: what an element predicate's member and a compiled
--!        predicate's `cmp` leaf each test of the entry they find.
--! @internal
--!
--! `gt` by `>`, `gte` by `>=`, `lt` by `<` and `lte` by `<=`, the ordering
--! operators an entry has against a {{prefix}}.query_json_leaf, joined by
--! SQL `AND`; a bound `bounds` does not carry is no test. So it is NULL
--! where a bound's comparison is: an entry that is NULL (no node at the
--! path) or has no ordering term.
--!
--! @param entry public.{{prefix}}_json_entry The entry.
--! @param bounds jsonb Bounds, as {{prefix}}_internal.json_tree_is_valid_bounds
--!        validates them; other keys (a member's `t`) are not read.
--! @return boolean Whether the entry satisfies every bound.
--! @note LANGUAGE sql and not STRICT, so it inlines into its callers.
CREATE FUNCTION {{prefix}}_internal.json_tree_within_bounds(entry public.{{prefix}}_json_entry, bounds jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT (NOT bounds ? 'gt' OR {{prefix}}.gt(entry, (bounds -> 'gt')::{{prefix}}.query_json_leaf))
     AND (NOT bounds ? 'gte' OR {{prefix}}.gte(entry, (bounds -> 'gte')::{{prefix}}.query_json_leaf))
     AND (NOT bounds ? 'lt' OR {{prefix}}.lt(entry, (bounds -> 'lt')::{{prefix}}.query_json_leaf))
     AND (NOT bounds ? 'lte' OR {{prefix}}.lte(entry, (bounds -> 'lte')::{{prefix}}.query_json_leaf))
$$;

--! @brief {{prefix}}.json_tree_element_match over a document already opened
--!        and indexed: what that function and {{prefix}}.json_tree_match
--!        each call, so a predicate with several element-scoped leaves
--!        opens and indexes its row once.
--! @internal
--! @param iv bytea The document's `iv`, which salts its self tags.
--! @param sv jsonb The document's entries.
--! @param tags jsonb The document's self tags, each mapped to the entry's
--!        ordinal in `sv`: the `nodes` {{prefix}}_internal.json_tree_index
--!        builds.
--! @param p jsonb The predicate, a valid {{prefix}}.query_json_elements.
--! @return boolean As {{prefix}}.json_tree_element_match.
--! @throws invalid_parameter_value As {{prefix}}.json_tree_element_match.
CREATE FUNCTION {{prefix}}_internal.json_tree_element_match_opened(iv bytea, sv jsonb, tags jsonb, p jsonb)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
  truncated boolean;
  matched boolean;
BEGIN
  WITH
    member AS MATERIALIZED (
      SELECT m.i,
             m.v,
             -- The selector of the member's field: every bound carries it.
             COALESCE(m.v -> 'gt', m.v -> 'gte', m.v -> 'lt', m.v -> 'lte') ->> 's' AS s
      FROM jsonb_array_elements(p -> 'm') WITH ORDINALITY AS m(v, i)
    ),
    -- The node each member's `k`-th token names, by its self tag; a token
    -- that names none yields no row.
    node AS MATERIALIZED (
      SELECT member.i, member.v, member.s, t.k, sv -> found.j AS entry
      FROM member
      CROSS JOIN LATERAL jsonb_array_elements_text(member.v -> 't') WITH ORDINALITY AS t(token, k)
      CROSS JOIN LATERAL (
        SELECT (tags ->> {{prefix}}_internal.json_tree_self_tag(iv, decode(t.token, 'base64')))::integer AS j
      ) AS found
      WHERE found.j IS NOT NULL
    ),
    satisfied AS (
      SELECT node.k
      FROM node
      CROSS JOIN LATERAL (SELECT node.entry::public.{{prefix}}_json_entry AS entry) AS typed
      WHERE node.entry ->> 's' = node.s
        AND {{prefix}}_internal.json_tree_within_bounds(typed.entry, node.v)
      GROUP BY node.k
      HAVING count(DISTINCT node.i) = (SELECT count(*) FROM member)
    )
  SELECT EXISTS (SELECT 1 FROM node WHERE node.entry ->> 's' IS DISTINCT FROM node.s),
         EXISTS (SELECT 1 FROM satisfied)
  INTO truncated, matched;

  IF truncated THEN
    RAISE EXCEPTION 'an array the element predicate reads is longer than the bound it was derived to, so the predicate would answer over part of it'
      USING ERRCODE = 'invalid_parameter_value',
            HINT = 'Derive the predicate (element_match) with a wildcard_bound past the longest array.';
  END IF;
  RETURN matched;
END;
$$;

--! @brief Whether some one element of an array in the document satisfies
--!        every member of an element-scoped predicate.
--!
--! The jsonpath `exists($.contacts[*] ? (@.relationship == $a &&
--! @.calls > $b))`: one element where both hold, which `@>` and an
--! ordering over `{{prefix}}.json_tree_path_query` cannot say together,
--! since each can be answered by a different element. Each member of
--! `p` holds the tokens of a subtree read of one field's path through the
--! array (`$.contacts[*].relationship`), in element order to one bound,
--! and that field's bounds. The function opens the document once, finds
--! the node each token of every member names, as
--! {{prefix}}.json_tree_subtree_indexed finds a token's node at `d = 0`
--! (by its self tag), and pairs the members' nodes by `k`, the token's
--! place in its member's array: the members' tokens were expanded to the
--! same bound in the same order, so one `k` is one element. Nothing
--! beneath a node is read: a member compares its field's own entry. It is true when some `k` has a node for every
--! member and each node satisfies its member's bounds, compared by the
--! ordering operators an entry has against a {{prefix}}.query_json_leaf:
--! `gt` by `>`, `gte` by `>=`, `lt` by `<`, `lte` by `<=`. An element where
--! a member's field is absent, or holds no ordering term (a container, a
--! boolean, a null), satisfies no bound of that member.
--!
--! **The probe.** Each member's tokens end with a probe: the token of the
--! element at the bound itself, which a document holds only when its array
--! is longer than the bound. A read finds the probe's node like any other,
--! and it is told apart by its selector: the element's, where every other
--! token names a node at the member's field, whose selector is the one the
--! member's bounds carry. A predicate over part of an array would answer
--! false for a row where an element past the bound matches, so a probe that
--! names a node raises rather than answer: derive the predicate with a
--! bound past the longest array, as a subtree read is raised.
--!
--! Equality rides on the ordering term, as `gte` and `lte` at one value, so
--! it is what the term compares: text case- and accent-folded, and numbers
--! as float64, so integers past 2^53 can tie. Containment (`@>`) is exact.
--!
--! @param e public.{{prefix}}_json_search The stored document.
--! @param p {{prefix}}.query_json_elements The predicate.
--! @return boolean True when one element satisfies every member; NULL when
--!         either argument is NULL.
--! @throws invalid_parameter_value when a member's probe names a node: the
--!         array is longer than the bound the predicate was derived to.
--! @note plpgsql, to raise, and so opaque to the planner: the call filters
--!       a scan, as a subtree read in a predicate does. Narrow the rows with
--!       an indexed predicate first, such as `@>` on the same values.
--! @see {{prefix}}_internal.json_tree_element_match_opened
CREATE FUNCTION {{prefix}}.json_tree_element_match(e public.{{prefix}}_json_search, p {{prefix}}.query_json_elements)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
  -- The document, decompressed once.
  d jsonb := e::jsonb #> '{}'::text[];
  tags jsonb;
BEGIN
  SELECT idx.nodes INTO tags FROM {{prefix}}_internal.json_tree_index(d) AS idx;
  RETURN {{prefix}}_internal.json_tree_element_match_opened(
    {{prefix}}_internal.json_tree_iv(d ->> 'h'), d -> 'sv', tags, p::jsonb);
END;
$$;
