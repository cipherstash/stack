-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/json_tree/functions.sql
-- REQUIRE: src/v3/json_tree/operators.sql
-- REQUIRE: src/v3/json_tree/elements.sql

--! @file v3/json_tree/predicate.sql
--! @brief A compiled predicate on public.{{prefix}}_json_search: a boolean
--!        tree of the family's query operands, bound as one parameter and
--!        evaluated by {{prefix}}.json_tree_match or `@@`.
--!
--! A filter compiler that targets plaintext `jsonb_path_match(col, $1, $2)`
--! binds one predicate and its values. The database cannot evaluate a
--! jsonpath over ciphertext, so Stack Encrypt's `match` operator compiles
--! the jsonpath on the client into this tree, whose leaves are the operands
--! the family's operators already take, and the server evaluates the tree.
--!
--! @note The tree is evaluated inside a function, which is opaque to the
--!       planner: `col @@ $1` filters a scan, and engages no index. The
--!       operators the leaves stand for, written out in the WHERE clause
--!       (`col @> $1`, `(col -> $2) < $3`), engage the GIN and btree indexes
--!       and are the fast path.

--! @brief Validate a compiled predicate, recursively.
--! @internal
--!
--! A node is an object of exactly one key, which names its kind:
--!   - `{"and": [node, …]}`, `{"or": [node, …]}`: at least one node;
--!   - `{"not": node}`;
--!   - `{"contains": needle}`: a containment needle, as
--!     public.{{prefix}}_is_valid_json_tree_query_payload validates the
--!     {{prefix}}.query_json CHECK;
--!   - `{"exists": "…"}`: a path selector, base64;
--!   - `{"cmp": bounds}`: one or two ordering operands at one selector, as
--!     {{prefix}}_internal.json_tree_is_valid_bounds validates them;
--!   - `{"elements": predicate}`: an element-scoped predicate, as
--!     {{prefix}}_internal.json_tree_is_valid_elements_payload validates the
--!     {{prefix}}.query_json_elements CHECK.
--!
--! @param val jsonb Candidate node.
--! @return boolean True when `val` is a node.
--! @note plpgsql: the recursion and the subqueries over the children cannot
--!       be written as a CHECK expression.
CREATE OR REPLACE FUNCTION {{prefix}}_internal.json_tree_is_valid_predicate_payload(val jsonb)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
  kind text;
BEGIN
  IF jsonb_typeof(val) IS DISTINCT FROM 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(val)) <> 1 THEN
    RETURN false;
  END IF;
  SELECT key INTO kind FROM jsonb_object_keys(val) AS key;
  RETURN COALESCE(
    CASE kind
      WHEN 'and' THEN
        jsonb_typeof(val -> 'and') = 'array'
        AND jsonb_array_length(val -> 'and') >= 1
        AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(val -> 'and') AS child
          WHERE NOT {{prefix}}_internal.json_tree_is_valid_predicate_payload(child)
        )
      WHEN 'or' THEN
        jsonb_typeof(val -> 'or') = 'array'
        AND jsonb_array_length(val -> 'or') >= 1
        AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(val -> 'or') AS child
          WHERE NOT {{prefix}}_internal.json_tree_is_valid_predicate_payload(child)
        )
      WHEN 'not' THEN
        {{prefix}}_internal.json_tree_is_valid_predicate_payload(val -> 'not')
      WHEN 'contains' THEN
        public.{{prefix}}_is_valid_json_tree_query_payload(val -> 'contains')
      WHEN 'exists' THEN
        jsonb_typeof(val -> 'exists') = 'string'
      WHEN 'cmp' THEN
        {{prefix}}_internal.json_tree_is_valid_bounds(val -> 'cmp')
      WHEN 'elements' THEN
        {{prefix}}_internal.json_tree_is_valid_elements_payload(val -> 'elements')
      ELSE false
    END,
    false
  );
END;
$$;

--! @brief Domain type for a compiled predicate on a JSON tree document.
--!
--! A boolean tree, serialised as JSON, whose leaves are the family's query
--! operands, as Stack Encrypt's `match` operator compiles a jsonpath
--! predicate into it:
--!   - `{"and": [node, …]}`, `{"or": [node, …]}`, `{"not": node}`;
--!   - `{"contains": {{prefix}}.query_json}`: the document contains the
--!     needle, `col @> needle`;
--!   - `{"exists": selector}`: the document has a node at the path,
--!     `{{prefix}}.json_tree_path_exists(col, selector)`;
--!   - `{"cmp": {"gt" | "gte": leaf, "lt" | "lte": leaf}}`: the first entry
--!     at the bounds' selector against each bound, each leaf a
--!     {{prefix}}.query_json_leaf, `(col -> s) > gt AND (col -> s) < lt`;
--!   - `{"elements": {{prefix}}.query_json_elements}`: one element of an
--!     array satisfies every member,
--!     `{{prefix}}.json_tree_element_match(col, elements)`.
--! {{prefix}}.json_tree_match reads it.
--!
--! @note Construct from inline JSON via the DOMAIN cast:
--!       `'{"and":[{"exists":"…"},{"contains":{"sv":[…],"el":[]}}]}'::{{prefix}}.query_json_predicate`.
--!       An untyped literal on the right of `@@` does not resolve to the
--!       domain: write the cast, `col @@ $1::{{prefix}}.query_json_predicate`.
--! @see {{prefix}}.json_tree_match
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_json_predicate' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_json_predicate AS jsonb
      CHECK (
        {{prefix}}_internal.json_tree_is_valid_predicate_payload(VALUE)
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_json_predicate IS 'EQL JSON tree query operand (compiled predicate)';
END
$$;

--! @brief One node of a compiled predicate, over a document already opened.
--! @internal
--!
--! `and`, `or` and `not` follow SQL's three-valued logic, as the operators
--! the leaves stand for would combine in a hand-written WHERE: `and` is
--! false when a child is false, else NULL when a child is NULL, else true;
--! `or` the dual; `not` NULL of NULL. Children are read in order and the
--! read stops at the first child that decides the answer, so an element
--! leaf the answer does not depend on is not read and cannot raise.
--!
--! Each leaf answers as its operator does on the column:
--!   - `contains`: native `jsonb @>` of the document's projection over the
--!     needle, and over its `alt` when it carries one, the rule
--!     {{prefix}}.json_tree_contains applies (`col @> needle`), here over
--!     the projection the caller read once;
--!   - `exists`: {{prefix}}.json_tree_path_exists;
--!   - `cmp`: the first entry at the selector,
--!     {{prefix}}.json_tree_path_query_first (what `col -> s` returns),
--!     against its bounds by {{prefix}}_internal.json_tree_within_bounds,
--!     as an element member's entry is: NULL when the document has no node
--!     at the path or the node has no ordering term;
--!   - `elements`: {{prefix}}_internal.json_tree_element_match_opened over
--!     the index the caller built once.
--!
--! @param d jsonb The document, decompressed.
--! @param sv jsonb Its entries, or NULL when the predicate has no element
--!        leaf.
--! @param q jsonb Its containment projection.
--! @param iv bytea Its `iv`, or NULL when the predicate has no element
--!        leaf.
--! @param tags jsonb Its self tags, as {{prefix}}_internal.json_tree_index
--!        builds them, or NULL when the predicate has no element leaf.
--! @param node jsonb The node, valid.
--! @return boolean The node's answer: true, false or NULL.
--! @throws invalid_parameter_value As {{prefix}}.json_tree_element_match,
--!         from an element leaf that is read.
--! @note Not STRICT: the parts a predicate does not need are NULL.
CREATE FUNCTION {{prefix}}_internal.json_tree_match_node(d jsonb, sv jsonb, q jsonb, iv bytea, tags jsonb, node jsonb)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
AS $$
DECLARE
  child jsonb;
  answer boolean;
  result boolean;
  needle jsonb;
  bounds jsonb;
  entry public.{{prefix}}_json_entry;
BEGIN
  IF node ? 'and' THEN
    result := true;
    FOR child IN SELECT jsonb_array_elements(node -> 'and') LOOP
      answer := {{prefix}}_internal.json_tree_match_node(d, sv, q, iv, tags, child);
      IF answer IS FALSE THEN
        RETURN false;
      ELSIF answer IS NULL THEN
        result := NULL;
      END IF;
    END LOOP;
    RETURN result;
  ELSIF node ? 'or' THEN
    result := false;
    FOR child IN SELECT jsonb_array_elements(node -> 'or') LOOP
      answer := {{prefix}}_internal.json_tree_match_node(d, sv, q, iv, tags, child);
      IF answer IS TRUE THEN
        RETURN true;
      ELSIF answer IS NULL THEN
        result := NULL;
      END IF;
    END LOOP;
    RETURN result;
  ELSIF node ? 'not' THEN
    RETURN NOT {{prefix}}_internal.json_tree_match_node(d, sv, q, iv, tags, node -> 'not');
  ELSIF node ? 'contains' THEN
    needle := node -> 'contains';
    RETURN q @> (needle - 'alt')
        OR ((needle ? 'alt') AND q @> (needle -> 'alt'));
  ELSIF node ? 'exists' THEN
    RETURN {{prefix}}.json_tree_path_exists(d, node ->> 'exists');
  ELSIF node ? 'cmp' THEN
    bounds := node -> 'cmp';
    entry := {{prefix}}.json_tree_path_query_first(
      d, COALESCE(bounds -> 'gt', bounds -> 'gte', bounds -> 'lt', bounds -> 'lte') ->> 's');
    RETURN {{prefix}}_internal.json_tree_within_bounds(entry, bounds);
  ELSE
    RETURN {{prefix}}_internal.json_tree_element_match_opened(iv, sv, tags, node -> 'elements');
  END IF;
END;
$$;

--! @brief Whether a document satisfies a compiled predicate.
--!
--! The one-parameter form of a filter over a JSON tree column, for a
--! compiler that targets plaintext `jsonb_path_match(col, $1, $2)`: Stack
--! Encrypt's `match` operator compiles the jsonpath predicate and its
--! values into `p`, and the tree is evaluated here, each leaf as its
--! operator answers on the column (see
--! {{prefix}}_internal.json_tree_match_node). The answer is the
--! hand-written WHERE's: `{"and": [{"exists": s}, {"cmp": {"lt": l}}]}` is
--! `{{prefix}}.json_tree_path_exists(col, s) AND (col -> s) < l`, NULL
--! where that is NULL.
--!
--! The document is decompressed once, and indexed once when the predicate
--! has an element leaf, however many leaves read it. The `exists` and
--! `cmp` leaves each scan the decompressed entries, as their functions do.
--! Whether the predicate has an element leaf is one walk of the predicate,
--! which is small, per row: the projection `q` is read without asking, as
--! one key of the decompressed document costs less than the walk.
--!
--! @param e public.{{prefix}}_json_search The stored document.
--! @param p {{prefix}}.query_json_predicate The predicate.
--! @return boolean The predicate's answer: true, false, or NULL as SQL's
--!         three-valued logic gives it; NULL when either argument is NULL.
--! @throws invalid_parameter_value As {{prefix}}.json_tree_element_match,
--!         from an element leaf that is read.
--! @note plpgsql, and so opaque to the planner: the call filters a scan,
--!       and engages no index. Written out per operator, the same predicate
--!       engages the GIN index on {{prefix}}.json_tree_query(col) and the
--!       functional btrees on {{prefix}}.ord_term(col -> s), so narrow the
--!       rows with an indexed predicate beside it, or write the operators.
--! @see {{prefix}}.query_json_predicate
CREATE FUNCTION {{prefix}}.json_tree_match(e public.{{prefix}}_json_search, p {{prefix}}.query_json_predicate)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
DECLARE
  -- The document, decompressed once.
  d jsonb := e::jsonb #> '{}'::text[];
  node jsonb := p::jsonb;
  sv jsonb;
  q jsonb;
  iv bytea;
  tags jsonb;
BEGIN
  q := d -> 'q';
  IF node @? '$.**.elements' THEN
    sv := d -> 'sv';
    iv := {{prefix}}_internal.json_tree_iv(d ->> 'h');
    SELECT idx.nodes INTO tags FROM {{prefix}}_internal.json_tree_index(d) AS idx;
  END IF;
  RETURN {{prefix}}_internal.json_tree_match_node(d, sv, q, iv, tags, node);
END;
$$;

--! @brief @@ operator with a compiled predicate: {{prefix}}.json_tree_match.
--!
--! `col @@ $1::{{prefix}}.query_json_predicate`. The operand MUST carry the
--! domain's type, as a typed parameter or an explicit cast; `@@` with a
--! `jsonpath` operand is blocked (blockers.sql), since the database cannot
--! evaluate a path over ciphertext.
--!
--! @param a public.{{prefix}}_json_search The stored document.
--! @param b {{prefix}}.query_json_predicate The predicate.
--! @return boolean As {{prefix}}.json_tree_match.
CREATE FUNCTION {{prefix}}."@@"(a public.{{prefix}}_json_search, b {{prefix}}.query_json_predicate)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_match(a, b)
$$;

CREATE OPERATOR @@(
  FUNCTION={{prefix}}."@@",
  LEFTARG=public.{{prefix}}_json_search,
  RIGHTARG={{prefix}}.query_json_predicate
);
