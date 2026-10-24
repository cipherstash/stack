-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql

--! @file v3/json_tree/types.sql
--! @brief Domain types for the {{prefix}} JSON tree surface: an encrypted JSON
--!        document stored as one entry per node, with node-local ciphertexts,
--!        a token chain and exact containment.
--!
--! This is a new domain family beside `public.{{prefix}}_json`, for documents
--! Stack Encrypt's JSON index writes. It shares no wire shape and no SQL with
--! the SteVec surface. Four jsonb-backed domains (none over another domain,
--! so the native-jsonb firewall in blockers.sql attaches):
--!   - public.{{prefix}}_json_tree       — storage: an EQL envelope `{v, i, h, sv, q}`.
--!   - public.{{prefix}}_json_tree_entry — one `sv` element (returned by `->`
--!                                        and the subtree walk).
--!   - {{prefix}}.query_json_tree         — a containment needle: the element-nested
--!                                        projection of the needle's selectors.
--!   - {{prefix}}.query_json_tree_leaf    — an ordering operand at a path: a
--!                                        selector and a leaf ordering term.
--!
--! The design is `docs/plans/2026-10-17-json-tree-index.md`
--! at the repository root. The document's per-entry fields:
--!   `s`  path selector (16 bytes, base64): every element of an array shares its
--!        parent's, so a path reads `$.a[*].x`.
--!   `c`  the node's own ciphertext (RFC 1924 base85, which no SQL function
--!        decodes): its label, its kind and, for a scalar, its value. The
--!        root's is the whole document when the root is sealed (the default).
--!   `p`  the parent tag, the first eight bytes of
--!        `H("p" ‖ iv ‖ t(parent) ‖ LE32(o))` (base64), where `o` is the
--!        node's ordinal under its parent: present below the chain's heads.
--!        The ordinals under a node are dense from 0, so a walk holding
--!        `t(parent)` probes them in turn until the first miss, and derives
--!        each hit's own token as `H("t" ‖ t(parent) ‖ s ‖ LE32(o))` from
--!        the hit's selector. Nothing stores a token or an ordinal.
--!   `op` the leaf ordering term (CLLW OPE, base64) on number and string leaves.
--! The header `h` (base64) carries the document's data key material once; the
--! SQL reads only the sealed-root flag at byte offset 1 and the ZeroKMS `iv`
--! at byte offset 22 of it, the per-document salt of the parent tags, and
--! otherwise carries it opaquely. `q` is the document's containment
--! projection, `{"sv": [{s, vs}, …], "el": [group, …]}`: one `{s, vs}` pair
--! per node, `vs` being the value selector of the node's kind and, for a
--! scalar, its value, bound to `s`, nested by array element. The client
--! writes it beside `sv` and it is the only place the value selectors
--! live: the server compares it with a needle by native `jsonb @>`.
--! The CHECK validates its shape, not that it agrees with `sv`: containment
--! answers from `q` as written, so a row written by anything but Stack
--! Encrypt's JSON index can answer `@>` differently from `->`, the walks
--! and decryption, which answer from `sv`.

--! @brief Validate one JSON tree entry.
--! @internal
--! @param val jsonb Candidate entry.
--! @return boolean True when `val` is an object with string `s` and `c`,
--!         optional string `p` and `op`, and the metadata the extractors
--!         graft: string `h`, numeric `j` (the entry's ordinal in the
--!         document) and `d` (its depth below a walk's start), and the
--!         envelope's `v` and `i`. No other key.
CREATE OR REPLACE FUNCTION public.{{prefix}}_is_valid_json_tree_entry_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND jsonb_typeof(val -> 's') = 'string'
     AND jsonb_typeof(val -> 'c') = 'string'
     AND (NOT (val ? 'p') OR jsonb_typeof(val -> 'p') = 'string')
     AND (NOT (val ? 'op') OR jsonb_typeof(val -> 'op') = 'string')
     AND (NOT (val ? 'h') OR jsonb_typeof(val -> 'h') = 'string')
     AND (NOT (val ? 'j') OR jsonb_typeof(val -> 'j') = 'number')
     AND (NOT (val ? 'd') OR jsonb_typeof(val -> 'd') = 'number')
     AND val - ARRAY['s', 'c', 'p', 'op', 'h', 'j', 'd', 'v', 'i']::text[] = '{}'::jsonb,
    false
  )
$$;

--! @brief Validate one group of a containment needle, recursively.
--! @internal
--!
--! A group is `{"sv": [{"s": "…", "vs": "…"}, …], "el": [group, …]}`: the
--! selector pairs that sit directly in it, and one nested group per array
--! element that is a container. The same shape a stored document carries
--! in `q`, its own projection, so native `jsonb @>` over the two is exact
--! containment. Validates both: a needle at its cast, a document's `q` at
--! its write.
--!
--! @param val jsonb Candidate group.
--! @return boolean True when `val` is a group.
--! @note plpgsql: the recursion and the subqueries over the arrays cannot be
--!       written as a CHECK expression, and a plpgsql body caches its plan
--!       across the per-needle casts on the query hot path.
CREATE OR REPLACE FUNCTION {{prefix}}_internal.json_tree_is_valid_query_group(val jsonb)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
BEGIN
  RETURN COALESCE(
    jsonb_typeof(val) = 'object'
     AND jsonb_typeof(val -> 'sv') = 'array'
     AND jsonb_typeof(val -> 'el') = 'array'
     AND val - ARRAY['sv', 'el']::text[] = '{}'::jsonb
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(val -> 'sv') AS pair
       WHERE NOT COALESCE(
         jsonb_typeof(pair) = 'object'
         AND jsonb_typeof(pair -> 's') = 'string'
         AND jsonb_typeof(pair -> 'vs') = 'string'
         AND pair - ARRAY['s', 'vs']::text[] = '{}'::jsonb,
         false)
     )
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(val -> 'el') AS grp
       WHERE NOT {{prefix}}_internal.json_tree_is_valid_query_group(grp)
     ),
    false
  );
END;
$$;

--! @brief Validate a JSON tree document.
--! @internal
--! @param val jsonb Candidate document.
--! @return boolean True when `val` is an envelope with `v = {{eql_version}}`, `i`, a
--!         string header `h`, a non-empty `sv` array of valid entries and
--!         the document's containment projection `q`, a group, and no
--!         other key. A document always has a root, so `sv` is never empty.
CREATE OR REPLACE FUNCTION public.{{prefix}}_is_valid_json_tree_document_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND val ? 'v'
     AND val ->> 'v' = '{{eql_version}}'
     AND val ? 'i'
     AND jsonb_typeof(val -> 'h') = 'string'
     AND jsonb_typeof(val -> 'sv') = 'array'
     AND jsonb_array_length(val -> 'sv') >= 1
     AND val - ARRAY['v', 'i', 'h', 'sv', 'q']::text[] = '{}'::jsonb
     AND NOT EXISTS (
       SELECT 1
       FROM jsonb_array_elements(val -> 'sv') AS elem
       WHERE NOT public.{{prefix}}_is_valid_json_tree_entry_payload(elem)
     )
     AND {{prefix}}_internal.json_tree_is_valid_query_group(val -> 'q'),
    false
  )
$$;

--! @brief Validate a containment needle.
--! @internal
--! @param val jsonb Candidate needle.
--! @return boolean True when `val` is a group (`sv`, `el`) with an optional
--!         `alt` group beside it: the alternative projection a needle whose
--!         root is a scalar carries, so that a stored root array holding the
--!         scalar matches as `jsonb @>` says it does.
CREATE OR REPLACE FUNCTION public.{{prefix}}_is_valid_json_tree_query_payload(val jsonb)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
BEGIN
  RETURN COALESCE(
    jsonb_typeof(val) = 'object'
     AND {{prefix}}_internal.json_tree_is_valid_query_group(val - 'alt')
     AND (NOT (val ? 'alt') OR {{prefix}}_internal.json_tree_is_valid_query_group(val -> 'alt')),
    false
  );
END;
$$;

--! @brief Storage domain for an encrypted JSON tree column.
--!
--! CHECK: the EQL envelope (`v = {{eql_version}}`, `i`, `h`) around a non-empty `sv`
--! array of valid entries and the projection `q`. The firewall in
--! blockers.sql attaches to this domain to stop native jsonb operators from
--! reaching a column value.
--!
--! @note Constructing from inline JSON uses the standard DOMAIN cast:
--!       `'{"v":{{eql_version}},"i":{…},"h":"…","sv":[…],"q":{…}}'::public.{{prefix}}_json_tree`.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_json_tree' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_json_tree AS jsonb
      CHECK (
        public.{{prefix}}_is_valid_json_tree_document_payload(VALUE)
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_json_tree IS 'EQL encrypted JSON tree document (containment, token chain)';
END
$$;

--! @brief Domain type for one entry of a JSON tree document.
--!
--! What `->`, the path functions and the subtree walk return: the entry with
--! the document's `h`, `v` and `i` and its own ordinal `j` grafted on, so it
--! opens on its own. A walk also grafts `d`, the entry's depth below the
--! walk's start.
--!
--! @note The CHECK calls the validator rather than inlining it: an entry is
--!       constructed by the extractors, not cast on the query hot path.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = '{{prefix}}_json_tree_entry' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.{{prefix}}_json_tree_entry AS jsonb
      CHECK (
        VALUE IS NULL OR public.{{prefix}}_is_valid_json_tree_entry_payload(VALUE)
      );
  END IF;

  COMMENT ON DOMAIN public.{{prefix}}_json_tree_entry IS 'EQL encrypted JSON tree entry (one node)';
END
$$;

--! @brief Domain type for a JSON tree containment needle.
--!
--! The element-nested projection of the needle's selectors, as Stack
--! Encrypt's `JsonQuery` serializes it: `{"sv": [{"s", "vs"}, …], "el":
--! [group, …], "alt": group?}`: the shape a stored document's `q` has, with
--! the optional `alt` beside it. Typing the needle this way stops raw jsonb
--! from casting and matching every row via bare `jsonb @>`.
--!
--! @note Construct from inline JSON via the DOMAIN cast:
--!       `'{"sv":[…],"el":[]}'::{{prefix}}.query_json_tree`.
--! @see {{prefix}}.json_tree_query
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_json_tree' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_json_tree AS jsonb
      CHECK (
        public.{{prefix}}_is_valid_json_tree_query_payload(VALUE)
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_json_tree IS 'EQL JSON tree query operand (containment)';
END
$$;

--! @brief Domain type for an ordering operand at a JSON path.
--!
--! `{"s": "…", "op": "…"}`: the path's selector, which `->` takes, and the
--! leaf ordering term the stored leaf's `op` compares against, as Stack
--! Encrypt's `JsonLeafQuery` serializes it. One operand serves `<`, `<=`,
--! `>` and `>=` on an extracted entry; a range at a path is two predicates.
--!
--! @note Construct from inline JSON via the DOMAIN cast:
--!       `'{"s":"…","op":"…"}'::{{prefix}}.query_json_tree_leaf`.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_json_tree_leaf' AND typnamespace = '{{prefix}}'::regnamespace
  ) THEN
    CREATE DOMAIN {{prefix}}.query_json_tree_leaf AS jsonb
      CHECK (
        VALUE IS NULL
        OR COALESCE(
          jsonb_typeof(VALUE) = 'object'
           AND jsonb_typeof(VALUE -> 's') = 'string'
           AND jsonb_typeof(VALUE -> 'op') = 'string'
           AND VALUE - ARRAY['s', 'op']::text[] = '{}'::jsonb,
          false
        )
      );
  END IF;

  COMMENT ON DOMAIN {{prefix}}.query_json_tree_leaf IS 'EQL JSON tree query operand (ordering at a path)';
END
$$;
