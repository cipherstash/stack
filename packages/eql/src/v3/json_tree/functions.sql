-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql

--! @file v3/json_tree/functions.sql
--! @brief The JSON tree surface's functions: the chain primitives, the
--!        containment projection, extraction by selector, the subtree walk
--!        by token, and the ordering extractors.
--!
--! Everything here is core PostgreSQL: `sha256(bytea)`, `get_byte` /
--! `set_byte`, `decode` / `encode`, recursive CTEs and `jsonb` operators. No
--! extension, no superuser, so the surface installs wherever the rest of
--! {{prefix}} does.
--!
--! `selector` parameters are *encrypted-side* selectors, the base64 the index
--! emits in `s`; `token` parameters are the base64 of a chain token the client
--! derived from a path. Plaintext paths are never accepted.

------------------------------------------------------------------------------
-- Chain primitives ({{prefix}}_internal)
------------------------------------------------------------------------------

--! @brief The first sixteen bytes of SHA-256 over `x`.
--! @internal
--! @param x bytea The bytes to hash.
--! @return bytea Sixteen bytes.
CREATE FUNCTION {{prefix}}_internal.json_tree_h16(x bytea)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT substr(sha256(x), 1, 16)
$$;

--! @brief A 32-bit integer as four little-endian bytes.
--! @internal
--! @param n integer The integer, non-negative.
--! @return bytea Four bytes, least significant first.
CREATE FUNCTION {{prefix}}_internal.json_tree_le32(n integer)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT set_byte(set_byte(set_byte(set_byte('\x00000000'::bytea,
    0, n & 255), 1, (n >> 8) & 255), 2, (n >> 16) & 255), 3, (n >> 24) & 255)
$$;

--! @brief The document's ZeroKMS `iv` from its header: the per-document salt
--!        of every chain tag.
--! @internal
--! @param h text The document's header, base64.
--! @return bytea Sixteen bytes, at byte offset 22 of the header's frozen
--!         layout (version, flags, epoch, keyset id, iv, tag).
CREATE FUNCTION {{prefix}}_internal.json_tree_iv(h text)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT substr(decode(h, 'base64'), 23, 16)
$$;

--! @brief The parent tag a child at ordinal `o` under the node with token
--!        `token` carries: the first eight bytes of
--!        `H("p" ‖ iv ‖ token ‖ LE32(o))`. Eight, since the tag is a lookup
--!        key within one document and nothing else: an entry's AAD binds
--!        its selector and ordinal, not its parent tag.
--! @internal
--! @param iv bytea The document's iv.
--! @param token bytea The parent's token, sixteen bytes.
--! @param o integer The child's ordinal.
--! @return text The tag, padded base64, as the entry's `p` spells it.
CREATE FUNCTION {{prefix}}_internal.json_tree_parent_tag(iv bytea, token bytea, o integer)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT encode(substr({{prefix}}_internal.json_tree_h16('p'::bytea || iv || token || {{prefix}}_internal.json_tree_le32(o)), 1, 8), 'base64')
$$;

--! @brief The token of the child at ordinal `o` under the node with token
--!        `token`, whose selector is `s`: `H("t" ‖ token ‖ s ‖ LE32(o))`.
--!        Column-wide like every token, with no document salt, so a client
--!        derives an array element's token from the path alone and the walk
--!        derives a hit's token from its parent's and the hit's own `s` on
--!        the spot. Nothing stores a token. The selector keeps an array
--!        element apart from an object member at the same ordinal, which a
--!        row whose node at the path is an object would otherwise put there.
--! @internal
--! @param token bytea The parent's token, sixteen bytes.
--! @param s bytea The child's selector, sixteen bytes.
--! @param o integer The child's ordinal.
--! @return bytea The child's token, sixteen bytes.
CREATE FUNCTION {{prefix}}_internal.json_tree_child_token(token bytea, s bytea, o integer)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_h16('t'::bytea || token || s || {{prefix}}_internal.json_tree_le32(o))
$$;

--! @brief Whether the document's root is sealed: its header's sealed-root
--!        flag, bit 0 of the flags byte at offset 1 of the frozen layout.
--!        A sealed root's `c` is the whole document, so a walk may return
--!        the root in place of a subtree it would be cheaper to open whole.
--! @internal
--! @param h text The document's header, base64.
--! @return boolean True when the root is sealed.
CREATE FUNCTION {{prefix}}_internal.json_tree_sealed_root(h text)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (get_byte(decode(h, 'base64'), 1) & 1) = 1
$$;

--! @brief The CLLW OPE term of a JSON tree entry or ordering operand: its
--!        `op`, base64-decoded. The JSON tree spells `op` in base64 like
--!        its other fields, where the scalar types' shared
--!        `{{prefix}}_internal.ope_cllw(jsonb)` reads hex, so the family
--!        has its own extractor.
--! @internal
--! @param val jsonb An entry or a `query_json_tree_leaf`, as jsonb.
--! @return {{prefix}}_internal.ope_cllw The term; NULL when there is none.
CREATE FUNCTION {{prefix}}_internal.json_tree_ope_cllw(val jsonb)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT decode(val ->> 'op', 'base64')::{{prefix}}_internal.ope_cllw
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_ope_cllw(jsonb) IS
  'eql-inline-critical: raw-jsonb CLLW OPE extractor of the JSON tree family; must stay inlinable (unpinned search_path)';

--! @brief The chained entries of a document keyed by parent tag: one object
--!        whose keys are each entry's `p` and whose values are the entry
--!        with its ordinal `j` in `sv` added. A walk looks a child up by
--!        the tag it computes, `map -> tag`, instead of scanning `sv` for
--!        it, so the document is read once per walk and a probe costs one
--!        hash and one lookup, not a pass over the document.
--! @internal
--! @param val jsonb The document.
--! @return jsonb The map; `{}` for a document with no chained entry.
CREATE FUNCTION {{prefix}}_internal.json_tree_by_parent(val jsonb)
  RETURNS jsonb
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_object_agg(elem ->> 'p', elem || jsonb_build_object('j', ord - 1)),
    '{}'::jsonb)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
  WHERE elem ? 'p'
$$;

------------------------------------------------------------------------------
-- Envelope helpers
------------------------------------------------------------------------------

--! @brief The envelope metadata an extracted entry carries: `i`, `v`, `h`.
--! @param val jsonb The document.
--! @return jsonb `{i, v, h}`, with absent keys dropped.
CREATE FUNCTION {{prefix}}.json_tree_meta(val jsonb)
  RETURNS jsonb
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT jsonb_strip_nulls(
    jsonb_build_object('i', val -> 'i', 'v', val -> 'v', 'h', val -> 'h')
  )
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_meta(jsonb) IS
  'eql-inline-critical: raw-jsonb envelope helper used by the JSON tree extractors; must stay inlinable (unpinned search_path)';

--! @brief The entry at ordinal `j` of the document, with the metadata grafted:
--!        what every extractor returns per node.
--! @internal
--! @param val jsonb The document.
--! @param elem jsonb The entry, as it sits in `sv`.
--! @param j integer The entry's ordinal in `sv`, from zero.
--! @return public.{{prefix}}_json_tree_entry The entry with `i`, `v`, `h` and `j`.
CREATE FUNCTION {{prefix}}_internal.json_tree_graft(val jsonb, elem jsonb, j integer)
  RETURNS public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT ({{prefix}}.json_tree_meta(val) || elem || jsonb_build_object('j', j))::public.{{prefix}}_json_tree_entry
$$;

------------------------------------------------------------------------------
-- Extraction by selector
------------------------------------------------------------------------------

--! @brief Every entry whose path selector is `selector`, as rows.
--!
--! Every element of an array shares its parent's selector, so a wildcard
--! path (`$.tags[*]`) returns one row per element. Each row opens on its
--! own: it carries the document's header `h` and its own ordinal `j`.
--!
--! @param val jsonb The document.
--! @param selector text The path selector, base64.
--! @return SETOF public.{{prefix}}_json_tree_entry The matching entries, in
--!         document order.
CREATE FUNCTION {{prefix}}.json_tree_path_query(val jsonb, selector text)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_graft(val, elem, (ord - 1)::integer)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
  WHERE elem ->> 's' = selector
  ORDER BY ord
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_path_query(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path query helper; must stay inlinable (unpinned search_path)';

--! @brief The first entry whose path selector is `selector`, or NULL: what
--!        `->` returns, and what the ordering comparisons extract.
--!
--! Costed at 1000 (ten times the default): the body scans `sv`, and its
--! cost is what decides whether a comparison on it, `(col -> sel) > $1`,
--! takes the functional btree on `{{prefix}}.ord_term(col -> sel)` or filters
--! a sequential scan. Under a prepared statement's generic plan, where the
--! operand's selectivity is a guess, the default cost chose the scan.
--!
--! @param val jsonb The document.
--! @param selector text The path selector, base64.
--! @return public.{{prefix}}_json_tree_entry The entry, or NULL when the document
--!         has no node at that path.
CREATE FUNCTION {{prefix}}.json_tree_path_query_first(val jsonb, selector text)
  RETURNS public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
  COST 1000
AS $$
  SELECT {{prefix}}_internal.json_tree_graft(val, elem, (ord - 1)::integer)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
  WHERE elem ->> 's' = selector
  ORDER BY ord
  LIMIT 1
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_path_query_first(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path first helper; must stay inlinable (unpinned search_path)';

--! @brief Whether the document has a node at the path `selector` names.
--! @param val jsonb The document.
--! @param selector text The path selector, base64.
--! @return boolean True when some entry carries the selector.
CREATE FUNCTION {{prefix}}.json_tree_path_exists(val jsonb, selector text)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM jsonb_array_elements(val -> 'sv') AS elem
    WHERE elem ->> 's' = selector
  )
$$;

COMMENT ON FUNCTION {{prefix}}.json_tree_path_exists(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path exists helper; must stay inlinable (unpinned search_path)';

------------------------------------------------------------------------------
-- Containment: the element-nested projection
------------------------------------------------------------------------------

--! @brief The stored document's containment projection: the needle shape
--!        `{{prefix}}.query_json_tree` holds, as the client wrote it in `q`.
--!
--! The projection is the document's `{s, vs}` pairs nested by array
--! element, `{"sv": [{"s", "vs"}, …], "el": [group, …]}`: the pairs outside
--! any array element at the top, and one nested group per array element
--! that is a container, so that `jsonb @>` over a stored projection and a
--! needle is PostgreSQL's own containment rule, each needle element inside
--! one stored element. The client derives it from the document it seals
--! and stores it beside `sv`; the server reads it and never rebuilds it,
--! so a containment recheck costs a field read, not a pass over `sv`.
--!
--! This is the GIN index expression for containment:
--!   `CREATE INDEX … USING gin (({{prefix}}.json_tree_query(col)) jsonb_path_ops);`
--! The typed `@>` inlines to native `jsonb @>` over the same expression, so
--! the index engages; GIN is lossy and the executor rechecks the real
--! operator on the heap tuple, which is the exact containment.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @return jsonb Its projection, the shape of `{{prefix}}.query_json_tree`.
--! @note Returns raw jsonb rather than the needle domain: a domain cast
--!       runs the needle's recursive CHECK, and the recheck would pay it
--!       once per candidate row. The document's own CHECK validated `q`
--!       when the row was written.
--! @note plpgsql, deliberately, and costed at 1000: a SQL body this simple
--!       would be inlined to `value -> 'q'`, which the planner costs as one
--!       operator, and a column of large documents is TOASTed out of the
--!       heap, so a sequential scan over it looks almost free on paper and
--!       is chosen over the GIN index. It is not free: every row is
--!       decompressed to read `q`. Un-inlined, the call keeps its cost, the
--!       index expression still matches it, and the planner takes the
--!       index. The call itself is a few microseconds per recheck row.
CREATE FUNCTION {{prefix}}.json_tree_query(e public.{{prefix}}_json_tree)
  RETURNS jsonb
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
  COST 1000
AS $$
BEGIN
  RETURN e::jsonb -> 'q';
END;
$$;

--! @brief Does the stored document `a` contain the needle `b`?
--!
--! Native `jsonb @>` over the projections, plus the needle's `alt` projection
--! when it carries one (a root scalar against a stored root array). Both
--! probes are over `{{prefix}}.json_tree_query(a)`, so a GIN index on that
--! expression serves them as one bitmap OR.
--!
--! @param a public.{{prefix}}_json_tree The stored document.
--! @param b {{prefix}}.query_json_tree The needle.
--! @return boolean True when `a` contains `b` as `jsonb @>` would contain the
--!         plaintexts; NULL when either is NULL.
--! @note Deliberately not STRICT. The planner inlines a STRICT SQL function
--!       only when it can prove the body is NULL for a NULL argument, and
--!       `x OR y` is not provably NULL. Un-inlined, the call is an opaque
--!       filter and the GIN index never engages. The body returns NULL for
--!       a NULL argument on its own: a NULL side of `@>` is NULL, and NULL
--!       OR NULL is NULL.
CREATE FUNCTION {{prefix}}.json_tree_contains(a public.{{prefix}}_json_tree, b {{prefix}}.query_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_query(a) @> (b::jsonb - 'alt')
      OR ((b::jsonb ? 'alt') AND {{prefix}}.json_tree_query(a) @> (b::jsonb -> 'alt'))
$$;

--! @brief Is the stored document `a` contained by the needle `b`?
--!
--! The projections the other way round. A stored document carries no `alt`,
--! so a stored root scalar inside a needle root array is the one case this
--! answers false where `jsonb <@` answers true.
--!
--! @param a public.{{prefix}}_json_tree The stored document.
--! @param b {{prefix}}.query_json_tree The needle.
--! @return boolean True when `b` contains `a`.
CREATE FUNCTION {{prefix}}.json_tree_contained_by(a public.{{prefix}}_json_tree, b {{prefix}}.query_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (b::jsonb - 'alt') @> {{prefix}}.json_tree_query(a)
$$;

--! @brief Does the stored document `a` contain the stored document `b`?
--! @param a public.{{prefix}}_json_tree The container.
--! @param b public.{{prefix}}_json_tree The contained document.
--! @return boolean True when `a`'s projection contains `b`'s.
CREATE FUNCTION {{prefix}}.json_tree_document_contains(a public.{{prefix}}_json_tree, b public.{{prefix}}_json_tree)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_query(a) @> {{prefix}}.json_tree_query(b)
$$;

------------------------------------------------------------------------------
-- The token chain: children and subtrees by token
------------------------------------------------------------------------------

--! The walk, in every function below. A node's children sit at the dense
--! ordinals `0, 1, 2, …` under it, and a child's parent tag is
--! `H("p" ‖ iv ‖ t(parent) ‖ LE32(o))`. So from a token the walk probes
--! ordinal 0, then 1, and so on, looking each tag up in the document's
--! parent map ({{prefix}}_internal.json_tree_by_parent), and stops at the
--! first miss. A hit's own token is `H("t" ‖ t(parent) ‖ s ‖ LE32(o))`,
--! `s` being the hit's own selector, derived on the spot
--! ({{prefix}}_internal.json_tree_child_token), and the walk recurses under
--! it. A subtree of `N` nodes therefore costs about
--! `2N` probes, `N` hits and a miss for every node visited (the end of a
--! parent's children, or a leaf's lack of any), each probe one SHA-256 and
--! one map lookup, plus one SHA-256 per hit for its token: about `3N`
--! hashes whatever the document's width. The map and the header fields
--! are computed once per call, so the document is read once.
--!
--! **The bound.** A stored document is untrusted: its parent tags are not
--! authenticated, so whoever holds a token can write entries of any shape
--! under it. The walk still ends after at most one row per entry. A probe
--! `(t(parent), o)` finds at most one entry, since the map keeps one entry
--! per tag and entries sharing a `p` collapse into it; a hit's token is a
--! hash of that probe, so no two rows share a token and no probe is made
--! twice; and a miss adds no row. Each walk also reads its recursion
--! through `LIMIT` the entry count plus one, the seed row, so the bound
--! holds without relying on either fact: PostgreSQL computes a recursive
--! query only as far as its reader pulls rows, so the limit stops the
--! recursion and not only the output, and a walk of a sealed document
--! never reaches it.
--!
--! **Gates.** An object member's ordinal is a function of its siblings'
--! keys, which the client does not know, so the client derives a token
--! only for a chain head and the array positions that directly follow it,
--! and walks the rest through one gate per further step: either the step's selector,
--! which the entry at that depth must carry in `s`, or `#n:<selector>`, an
--! array position, which is the one ordinal probed at that depth and whose
--! entry must carry the array elements' selector, so that an object member
--! ranked at ordinal `n` in a row whose node there is an object is not
--! taken for an element. A wildcard step's selector is every element's, so
--! it admits them all. Entries are returned from the depth of the last gate
--! down: the node each gate chain reaches, and everything beneath it.

--! @brief The children of the node the gates reach from the node whose
--!        token is `token`, as rows.
--!
--! What `jsonb_array_elements` is for an encrypted array: one row per
--! element, in the document's order, each opening on its own. With no
--! gates, the children of the token's own node; with gates, the walk
--! descends through them as `json_tree_subtree_at` does and returns one
--! level below the node they reach.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The start node's token, base64: derived by the client
--!        from the path alone, and never stored.
--! @param gates text[] One gate per step below the token, as
--!        `json_tree_subtree_at` takes them. Default none.
--! @return SETOF public.{{prefix}}_json_tree_entry The children, each with `d = 1`.
CREATE FUNCTION {{prefix}}.json_tree_children(e public.{{prefix}}_json_tree, token text, gates text[] DEFAULT ARRAY[]::text[])
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_by_parent(e::jsonb) AS map,
             {{prefix}}.json_tree_meta(e::jsonb) AS meta,
             jsonb_array_length(e::jsonb -> 'sv') AS entries,
             COALESCE(array_length(gates, 1), 0) AS gated
    ),
    -- The walk of `json_tree_subtree_at`, cut one level below the gates.
    walk(depth, pt, o, entry, t, ppass, pass) AS (
        SELECT 0, NULL::bytea, NULL::integer, NULL::jsonb, decode(token, 'base64'), true, true
      UNION ALL
        SELECT probe.depth, probe.pt, probe.o, hit.entry,
               {{prefix}}_internal.json_tree_child_token(probe.pt, decode(hit.entry ->> 's', 'base64'), probe.o),
               probe.ppass,
               probe.ppass AND (
                 probe.depth > doc.gated
                 OR hit.entry ->> 's' = CASE WHEN gates[probe.depth] LIKE '#%'
                                             THEN split_part(gates[probe.depth], ':', 2)
                                             ELSE gates[probe.depth] END)
        FROM walk AS w
        CROSS JOIN doc
        CROSS JOIN LATERAL (
          SELECT w.depth + 1 AS depth,
                 w.t AS pt,
                 CASE WHEN COALESCE(gates[w.depth + 1], '') LIKE '#%'
                      THEN split_part(substr(gates[w.depth + 1], 2), ':', 1)::integer
                      ELSE 0 END AS o,
                 w.pass AS ppass
          WHERE w.pass AND w.depth <= doc.gated
          UNION ALL
          SELECT w.depth, w.pt, w.o + 1, w.ppass
          WHERE w.entry IS NOT NULL AND COALESCE(gates[w.depth], '') NOT LIKE '#%'
        ) AS probe
        CROSS JOIN LATERAL (
          SELECT doc.map -> {{prefix}}_internal.json_tree_parent_tag(doc.iv, probe.pt, probe.o) AS entry
        ) AS hit
        WHERE hit.entry IS NOT NULL
    ),
    -- At most one row per entry and the seed (see "The bound" above).
    visited AS MATERIALIZED (
      SELECT w.* FROM walk AS w LIMIT (SELECT doc.entries + 1 FROM doc)
    )
  SELECT (doc.meta || w.entry || '{"d": 1}'::jsonb)::public.{{prefix}}_json_tree_entry
  FROM visited AS w, doc
  WHERE w.entry IS NOT NULL AND w.pass AND w.depth = doc.gated + 1
  ORDER BY (w.entry ->> 'j')::integer
$$;

--! @brief How many children the node the gates reach from `token` has:
--!        the length of an encrypted array, or the member count of an
--!        object.
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The start node's token, base64.
--! @param gates text[] One gate per step below the token. Default none.
--! @return integer The count; `0` for a node with no children, a token that
--!         names no node included.
CREATE FUNCTION {{prefix}}.json_tree_child_count(e public.{{prefix}}_json_tree, token text, gates text[] DEFAULT ARRAY[]::text[])
  RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT count(*)::integer FROM {{prefix}}.json_tree_children(e, token, gates)
$$;

--! @brief The entries under the node the gates reach from the node whose
--!        token is `token`, as rows: the recursive walk of the chain, in
--!        core SQL.
--!
--! Each level probes the ordinals under the node in hand until the first
--! miss, derives each hit's token, and recurses. A token that names no node
--! yields no row, and nothing in a row is linkable to anything without the
--! token. At depth `d` (1 below the token) the gate `gates[d]`, if there
--! is one, decides which hits the walk descends through: an entry whose
--! `s` is the gate's selector, or, for a gate `#n:<selector>`, the one hit
--! at ordinal `n` if it carries that selector. Rows are returned from the depth of the last gate down: the
--! node a gate chain reaches, with `d = 0`, and everything beneath it, with
--! `d` its depth below that node. The start node is never returned. With
--! no gates, every descendant of the start node, with `d` its depth below
--! it, from 1.
--!
--! **The budget.** A walk returns about two hundred characters per entry,
--! where a sealed root holds the whole document in one ciphertext of about
--! the plaintext's size. So when the root is sealed and the walk would
--! return more than `budget` entries, it stops and returns the root entry
--! alone, with `d = 0`: the client opens it to the whole document and takes
--! the path itself, which is cheaper on both sides than the walk past that
--! point. The default of 64 is past the crossover by bytes (about a dozen
--! entries) by a margin that keeps a small subtree arriving as the entries
--! it is. A `budget` of `0` never falls back. A token that names no node
--! yields no row under any budget, and a document whose root is not sealed
--! is always walked in full, since its root holds no document to return.
--!
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The start node's token, base64.
--! @param gates text[] One gate per step below the token: a selector, base64,
--!        or `#n:<selector>` for the array position `n`, with the array
--!        elements' selector. Empty for the whole subtree.
--! @param budget integer The most entries to return before falling back to
--!        the sealed root; `0` to always walk out. Default 64.
--! @return SETOF public.{{prefix}}_json_tree_entry The entries, each with its
--!         depth `d` below the node the gates reach, in document order; or
--!         the root entry alone, with `j = 0` and `d = 0`, past the budget.
CREATE FUNCTION {{prefix}}.json_tree_subtree_at(e public.{{prefix}}_json_tree, token text, gates text[], budget integer DEFAULT 64)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(e::jsonb ->> 'h') AS iv,
             {{prefix}}_internal.json_tree_by_parent(e::jsonb) AS map,
             {{prefix}}.json_tree_meta(e::jsonb) AS meta,
             e::jsonb -> 'sv' -> 0 AS root,
             jsonb_array_length(e::jsonb -> 'sv') AS entries,
             budget > 0 AND {{prefix}}_internal.json_tree_sealed_root(e::jsonb ->> 'h') AS capped,
             COALESCE(array_length(gates, 1), 0) AS gated
    ),
    -- One row per hit, after the seed row for the start node. `pt` and `o`
    -- are where the hit sits, its parent's token and its ordinal; `t` is its
    -- own token; `ppass` whether every gate down to its parent admitted the
    -- parent, `pass` whether this hit's gate admits it too.
    walk(depth, pt, o, entry, t, ppass, pass) AS (
        SELECT 0, NULL::bytea, NULL::integer, NULL::jsonb, decode(token, 'base64'), true, true
      UNION ALL
        SELECT probe.depth, probe.pt, probe.o, hit.entry,
               {{prefix}}_internal.json_tree_child_token(probe.pt, decode(hit.entry ->> 's', 'base64'), probe.o),
               probe.ppass,
               probe.ppass AND (
                 probe.depth > doc.gated
                 OR hit.entry ->> 's' = CASE WHEN gates[probe.depth] LIKE '#%'
                                             THEN split_part(gates[probe.depth], ':', 2)
                                             ELSE gates[probe.depth] END)
        FROM walk AS w
        CROSS JOIN doc
        CROSS JOIN LATERAL (
          -- Down: the first ordinal under this node, or the one position an
          -- array gate names, from a node its gates admitted.
          SELECT w.depth + 1 AS depth,
                 w.t AS pt,
                 CASE WHEN COALESCE(gates[w.depth + 1], '') LIKE '#%'
                      THEN split_part(substr(gates[w.depth + 1], 2), ':', 1)::integer
                      ELSE 0 END AS o,
                 w.pass AS ppass
          WHERE w.pass
          UNION ALL
          -- Across: the next ordinal under the same parent, from any hit,
          -- since a hit its gate refused still has siblings to find; not
          -- when an array gate pins this depth to one position.
          SELECT w.depth, w.pt, w.o + 1, w.ppass
          WHERE w.entry IS NOT NULL AND COALESCE(gates[w.depth], '') NOT LIKE '#%'
        ) AS probe
        CROSS JOIN LATERAL (
          SELECT doc.map -> {{prefix}}_internal.json_tree_parent_tag(doc.iv, probe.pt, probe.o) AS entry
        ) AS hit
        WHERE hit.entry IS NOT NULL
    ),
    -- At most one row per entry and the seed (see "The bound" above),
    -- whatever the budget: a budget of 0, or an open root, leaves `found`
    -- uncapped, and this is then the walk's only limit.
    visited AS MATERIALIZED (
      SELECT w.* FROM walk AS w LIMIT (SELECT doc.entries + 1 FROM doc)
    ),
    -- One row past the budget is enough to know the walk went over; a walk
    -- under it is the subtree complete. Uncapped, the limit is NULL: all
    -- that `visited` holds.
    found AS MATERIALIZED (
      SELECT w.depth, w.entry
      FROM visited AS w, doc
      WHERE w.entry IS NOT NULL AND w.pass AND w.depth >= doc.gated
      LIMIT (SELECT CASE WHEN doc.capped THEN budget + 1 END FROM doc)
    ),
    over AS MATERIALIZED (
      SELECT doc.capped AND (SELECT count(*) FROM found) > budget AS fallback FROM doc
    )
  SELECT rows.entry
  FROM (
    SELECT 0 AS j,
           (doc.meta || doc.root || '{"j": 0, "d": 0}'::jsonb)::public.{{prefix}}_json_tree_entry AS entry
    FROM doc, over
    WHERE over.fallback
    UNION ALL
    SELECT (f.entry ->> 'j')::integer,
           (doc.meta || f.entry || jsonb_build_object('d', f.depth - doc.gated))::public.{{prefix}}_json_tree_entry
    FROM found AS f, doc, over
    WHERE NOT over.fallback
  ) AS rows
  ORDER BY rows.j
$$;

--! @brief Every entry under the node whose token is `token`:
--!        `json_tree_subtree_at` with no gates.
--! @param e public.{{prefix}}_json_tree The stored document.
--! @param token text The subtree's token, base64.
--! @param budget integer The most entries to return before falling back to
--!        the sealed root; `0` to always walk the subtree out. Default 64.
--! @return SETOF public.{{prefix}}_json_tree_entry The descendants, each with its
--!         depth `d` below the node, in document order; or the root entry
--!         alone, with `d = 0`, past the budget.
CREATE FUNCTION {{prefix}}.json_tree_subtree(e public.{{prefix}}_json_tree, token text, budget integer DEFAULT 64)
  RETURNS SETOF public.{{prefix}}_json_tree_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT * FROM {{prefix}}.json_tree_subtree_at(e, token, ARRAY[]::text[], budget)
$$;

------------------------------------------------------------------------------
-- Ordering at a path
------------------------------------------------------------------------------

--! @brief The path selector of an entry.
--! @param entry public.{{prefix}}_json_tree_entry The entry.
--! @return text Its `s`, base64.
CREATE FUNCTION {{prefix}}.selector(entry public.{{prefix}}_json_tree_entry)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 's'
$$;

--! @brief The leaf ordering term of an entry, for ordered comparison.
--!
--! The CLLW OPE term the index derived for a number or string leaf, keyed by
--! the column, base64-decoded to the bytea-backed `{{prefix}}_internal.ope_cllw`
--! domain: native byte order is plaintext order, so a functional btree on
--! `{{prefix}}.ord_term(col -> 'selector')` engages with the DEFAULT opclass. NULL
--! for an entry with no term (a container, a boolean, a null), which btree's
--! NULL handling drops from range queries.
--!
--! Order rows by this, `ORDER BY {{prefix}}.ord_term(col -> 'sel')`, never by
--! the entry itself: `ORDER BY col -> 'sel'` uses jsonb's default ordering of
--! the entry object, which sorts by ciphertext, and an operator class that
--! would redirect it needs a superuser to install.
--!
--! @param entry public.{{prefix}}_json_tree_entry The entry.
--! @return {{prefix}}_internal.ope_cllw The term, or NULL.
CREATE FUNCTION {{prefix}}.ord_term(entry public.{{prefix}}_json_tree_entry)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_ope_cllw(entry::jsonb)
$$;

--! @brief The leaf ordering term of an ordering operand.
--! @param q {{prefix}}.query_json_tree_leaf The operand.
--! @return {{prefix}}_internal.ope_cllw Its `op`, base64-decoded.
CREATE FUNCTION {{prefix}}.ord_term(q {{prefix}}.query_json_tree_leaf)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_ope_cllw(q::jsonb)
$$;

--! @brief The path selector of an ordering operand: what `->` takes to reach
--!        the leaf the operand compares against.
--! @param q {{prefix}}.query_json_tree_leaf The operand.
--! @return text Its `s`, base64.
CREATE FUNCTION {{prefix}}.selector(q {{prefix}}.query_json_tree_leaf)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT q ->> 's'
$$;
