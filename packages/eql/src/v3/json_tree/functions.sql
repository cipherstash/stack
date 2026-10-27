-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql

--! @file v3/json_tree/functions.sql
--! @brief The JSON tree surface's functions: the chain primitives, the
--!        containment projection, extraction by selector, the subtree read
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

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_h16(bytea) IS
  'eql-inline-critical: chain primitive of the JSON tree family, evaluated per probe and per hit of a walk; must stay inlinable (unpinned search_path)';

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

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_le32(integer) IS
  'eql-inline-critical: chain primitive of the JSON tree family, evaluated per probe of a walk; must stay inlinable (unpinned search_path)';

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

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_parent_tag(bytea, bytea, integer) IS
  'eql-inline-critical: the probe of the JSON tree walk, evaluated once per ordinal visited; must stay inlinable (unpinned search_path)';

--! @brief The self tag of the node whose token is `token`: the first eight
--!        bytes of `H("x" ‖ iv ‖ token)`. Every entry carries its own in
--!        `x`, so the server finds the node a client-derived token names by
--!        computing this and looking it up. Eight bytes, since the tag is a
--!        lookup key within one document and nothing else: an entry's AAD
--!        binds its selector and ordinal, not its self tag.
--! @internal
--! @param iv bytea The document's iv.
--! @param token bytea The node's token, sixteen bytes.
--! @return text The tag, padded base64, as the entry's `x` spells it.
CREATE FUNCTION {{prefix}}_internal.json_tree_self_tag(iv bytea, token bytea)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT encode(substr({{prefix}}_internal.json_tree_h16('x'::bytea || iv || token), 1, 8), 'base64')
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_self_tag(bytea, bytea) IS
  'eql-inline-critical: the JSON tree walk evaluates it per token and per hit; must stay inlinable (unpinned search_path)';

--! @brief The token of the object member whose selector is `s`, under the
--!        object whose token is `token`: `H("t" ‖ token ‖ s)`. Column-wide
--!        like every token, with no document salt, and with no ordinal, so a
--!        client derives it from the path alone whatever else the object
--!        holds. Nothing stores a token.
--! @internal
--! @param token bytea The parent's token, sixteen bytes.
--! @param s bytea The member's selector, sixteen bytes.
--! @return bytea The member's token, sixteen bytes.
CREATE FUNCTION {{prefix}}_internal.json_tree_member_token(token bytea, s bytea)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_h16('t'::bytea || token || s)
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_member_token(bytea, bytea) IS
  'eql-inline-critical: the JSON tree walk evaluates it per hit; must stay inlinable (unpinned search_path)';

--! @brief The token of the array element at index `i`, whose selector is
--!        `s`, under the array whose token is `token`:
--!        `H("t" ‖ token ‖ s ‖ LE32(i))`. Every element of an array shares
--!        one selector, so an element keeps its index; the input is four
--!        bytes longer than a member's, so the two rules never meet.
--! @internal
--! @param token bytea The array's token, sixteen bytes.
--! @param s bytea The element's selector, sixteen bytes.
--! @param i integer The element's index.
--! @return bytea The element's token, sixteen bytes.
CREATE FUNCTION {{prefix}}_internal.json_tree_element_token(token bytea, s bytea, i integer)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_h16('t'::bytea || token || s || {{prefix}}_internal.json_tree_le32(i))
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_element_token(bytea, bytea, integer) IS
  'eql-inline-critical: the JSON tree walk evaluates it per hit; must stay inlinable (unpinned search_path)';

--! @brief The token of a child the walk found at ordinal `o` under the node
--!        whose token is `token`: the member rule's if the child's self tag
--!        `x` is that token's, else the element rule's if it is that one's,
--!        else NULL. Nothing stored says whether a node is a member or an
--!        element (its kind is inside `c`, and a selector does not say
--!        whether its path ends in a key), so the self tag is what chooses.
--!        Three hashes on a member, six on an element: the chosen token is
--!        derived twice, which is cheaper than the FROM clause that would
--!        hold it, since a FROM clause stops the planner inlining the
--!        function. Not STRICT for the same reason: a STRICT function whose
--!        body is a CASE is inlined only where every argument is provably
--!        non-null. The rules inside are STRICT, so a NULL argument makes
--!        both comparisons NULL and the CASE NULL.
--! @internal
--! @param iv bytea The document's iv.
--! @param token bytea The parent's token, sixteen bytes.
--! @param s bytea The child's selector, sixteen bytes.
--! @param o integer The child's ordinal: an element's index, or a member's
--!        place in the random permutation its object's members were given.
--! @param x text The child's stored self tag.
--! @return bytea The child's token, or NULL when neither rule's self tag is
--!         `x`, and the walk does not descend into it.
CREATE FUNCTION {{prefix}}_internal.json_tree_hit_token(iv bytea, token bytea, s bytea, o integer, x text)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN {{prefix}}_internal.json_tree_self_tag(iv, {{prefix}}_internal.json_tree_member_token(token, s)) = x
      THEN {{prefix}}_internal.json_tree_member_token(token, s)
    WHEN {{prefix}}_internal.json_tree_self_tag(iv, {{prefix}}_internal.json_tree_element_token(token, s, o)) = x
      THEN {{prefix}}_internal.json_tree_element_token(token, s, o)
  END
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_hit_token(bytea, bytea, bytea, integer, text) IS
  'eql-inline-critical: the JSON tree walk evaluates it per hit; must stay inlinable (unpinned search_path)';

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
--! @param val jsonb An entry or a `query_json_leaf`, as jsonb.
--! @return {{prefix}}_internal.ope_cllw The term; NULL when there is none.
CREATE FUNCTION {{prefix}}_internal.json_tree_ope_cllw(val jsonb)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT decode(val ->> 'op', 'base64')::{{prefix}}_internal.ope_cllw
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_ope_cllw(jsonb) IS
  'eql-inline-critical: raw-jsonb CLLW OPE extractor of the JSON tree family; must stay inlinable (unpinned search_path)';

--! @brief The positions of a document's entries by tag: `map`, the parent
--!        tag of every chained entry, and `nodes`, the self tag of every
--!        entry, each mapped to the entry's ordinal `j` in `sv`. A read
--!        finds the node a token names, and a walk each child it probes for,
--!        by the tag it computes, `nodes ->> tag` or `map ->> tag`, so a
--!        token or a probe costs one hash and one lookup, and the entry
--!        itself is fetched as `sv -> j` only when it is used. One pass over
--!        `sv` builds both maps. A map of the entries themselves, as the
--!        walk first had, copied every entry to build and cost four times as
--!        much as this on a document of two hundred entries, which was most
--!        of a one-token read.
--!
--!        Set-returning, with the two maps as columns, and not STRICT, so
--!        that the planner inlines it as a subquery of the caller's
--!        `LATERAL`: an aggregate subquery is computed once, where a scalar
--!        function the caller's subquery named twice (`idx -> 'p'`,
--!        `idx -> 'x'`) was evaluated twice when the planner flattened that
--!        subquery, and a STRICT set-returning function is not inlined at
--!        all. The aggregate over no rows is one row of two `{}`, for a
--!        NULL or empty `sv`.
--! @internal
--! @param val jsonb The document.
--! @return TABLE(map jsonb, nodes jsonb) One row: `map` `{p: j, …}` and
--!         `nodes` `{x: j, …}`, either `{}` when no entry carries that tag.
CREATE FUNCTION {{prefix}}_internal.json_tree_index(val jsonb)
  RETURNS TABLE(map jsonb, nodes jsonb)
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT COALESCE(jsonb_object_agg(elem ->> 'p', ord - 1) FILTER (WHERE elem ? 'p'), '{}'::jsonb),
         COALESCE(jsonb_object_agg(elem ->> 'x', ord - 1) FILTER (WHERE elem ? 'x'), '{}'::jsonb)
  FROM jsonb_array_elements(val -> 'sv') WITH ORDINALITY AS t(elem, ord)
$$;

COMMENT ON FUNCTION {{prefix}}_internal.json_tree_index(jsonb) IS
  'eql-inline-critical: the index every JSON tree read builds, inlined as a subquery so it is built once; must stay inlinable (unpinned search_path)';

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
--! @return public.{{prefix}}_json_entry The entry with `i`, `v`, `h` and `j`.
CREATE FUNCTION {{prefix}}_internal.json_tree_graft(val jsonb, elem jsonb, j integer)
  RETURNS public.{{prefix}}_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT ({{prefix}}.json_tree_meta(val) || elem || jsonb_build_object('j', j))::public.{{prefix}}_json_entry
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
--! @return SETOF public.{{prefix}}_json_entry The matching entries, in
--!         stored order, which says nothing about the document: entries
--!         are stored in a random order, and the client puts an array's
--!         elements back in order from their decrypted labels.
CREATE FUNCTION {{prefix}}.json_tree_path_query(val jsonb, selector text)
  RETURNS SETOF public.{{prefix}}_json_entry
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
--! @return public.{{prefix}}_json_entry The entry, or NULL when the document
--!         has no node at that path.
CREATE FUNCTION {{prefix}}.json_tree_path_query_first(val jsonb, selector text)
  RETURNS public.{{prefix}}_json_entry
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
--!        `{{prefix}}.query_json` holds, as the client wrote it in `q`.
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
--! @param e public.{{prefix}}_json_search The stored document.
--! @return jsonb Its projection, the shape of `{{prefix}}.query_json`.
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
CREATE FUNCTION {{prefix}}.json_tree_query(e public.{{prefix}}_json_search)
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
--! @param a public.{{prefix}}_json_search The stored document.
--! @param b {{prefix}}.query_json The needle.
--! @return boolean True when `a` contains `b` as `jsonb @>` would contain the
--!         plaintexts; NULL when either is NULL.
--! @note Deliberately not STRICT. The planner inlines a STRICT SQL function
--!       only when it can prove the body is NULL for a NULL argument, and
--!       `x OR y` is not provably NULL. Un-inlined, the call is an opaque
--!       filter and the GIN index never engages. The body returns NULL for
--!       a NULL argument on its own: a NULL side of `@>` is NULL, and NULL
--!       OR NULL is NULL.
CREATE FUNCTION {{prefix}}.json_tree_contains(a public.{{prefix}}_json_search, b {{prefix}}.query_json)
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
--! @param a public.{{prefix}}_json_search The stored document.
--! @param b {{prefix}}.query_json The needle.
--! @return boolean True when `b` contains `a`.
CREATE FUNCTION {{prefix}}.json_tree_contained_by(a public.{{prefix}}_json_search, b {{prefix}}.query_json)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (b::jsonb - 'alt') @> {{prefix}}.json_tree_query(a)
$$;

--! @brief Does the stored document `a` contain the stored document `b`?
--! @param a public.{{prefix}}_json_search The container.
--! @param b public.{{prefix}}_json_search The contained document.
--! @return boolean True when `a`'s projection contains `b`'s.
CREATE FUNCTION {{prefix}}.json_tree_document_contains(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}.json_tree_query(a) @> {{prefix}}.json_tree_query(b)
$$;

------------------------------------------------------------------------------
-- The token chain: nodes, children and subtrees by token
------------------------------------------------------------------------------

--! The read, in every function below. Every node's token derives from its
--! path alone, so the client sends the token of exactly the node it reads,
--! and the server finds that node by its self tag,
--! `x = H("x" ‖ iv ‖ token)`, looked up in the document's index
--! ({{prefix}}_internal.json_tree_index), which maps every entry's `x`, and
--! every chained entry's `p`, to the entry's position in `sv`. The node's
--! children sit at the dense ordinals `0, 1, 2, …` under it, and a child's
--! parent tag is `H("p" ‖ iv ‖ t(parent) ‖ LE32(o))`. So from a node's
--! token the walk probes ordinal 0, then 1, and so on, looking each tag up
--! in the index, and stops at the first miss. A hit's own token is the
--! member rule's, `H("t" ‖ t(parent) ‖ s)`, or the element rule's,
--! `H("t" ‖ t(parent) ‖ s ‖ LE32(o))`, `s` being the hit's own selector:
--! nothing stored says which, so the walk keeps whichever one's self tag is
--! the hit's `x` ({{prefix}}_internal.json_tree_hit_token), and does not
--! descend into a hit that matches neither. A subtree of `N` nodes
--! therefore costs one self-tag lookup, about `2N` probes (`N` hits and a
--! miss for every node visited), each one SHA-256 and one lookup, and three
--! to six SHA-256s per hit to choose its token. The index and the header
--! fields are computed once per call, so the document is read once, and an
--! entry is copied out of `sv` only when it is returned.
--!
--! **Inlining.** Every chain primitive a probe or a hit evaluates (the
--! hashes, the tags and the token rules; not `json_tree_iv` or
--! `json_tree_sealed_root`, read once per call) carries the
--! `eql-inline-critical` marker that keeps its search_path unpinned: the planner does not inline a function with a
--! pinned search_path, and a probe then costs a full SQL-function call,
--! about ten microseconds, against under one for the hashes it performs.
--! For the same reason a hit's token is derived where it is consumed, in
--! the probe beneath it, from the hit's stored `s` and `x` read off the
--! working table: the planner inlines a function that uses an argument more
--! than once only when that argument is a cheap expression, and the
--! expression that locates a hit is not.
--!
--! **One decompression.** The stored document is TOAST-compressed, and
--! every reference to the function's argument decompresses it again: the
--! header, `sv`, the metadata, the entry count and the index each cost a
--! decompression of the whole document, about forty microseconds for a
--! nested document of two hundred entries, a third of a one-token read.
--! So each read first takes `e::jsonb #> '{}'`, the identity path, into a
--! MATERIALIZED CTE: the operator returns the decompressed document, and
--! everything below reads that.
--!
--! **The bound.** A stored document is untrusted: its self tags and parent
--! tags are not authenticated, so whoever holds a token can write entries
--! of any shape under it. A probe `(t(parent), o)` finds at most one entry,
--! since the index keeps one position per tag, and a miss adds no row. But
--! a member's token is a hash of its parent's token and its selector, not
--! of the probe, so two entries forged under one parent with one selector
--! and the member rule's self tag derive one token, and the walk visits the
--! subtree beneath it once for each: forged level after level, the rows
--! would double at every level. So {{prefix}}.json_tree_subtree reads its
--! recursion through `LIMIT` the entry count times the number of tokens: a
--! sealed document's nodes each sit under one token of a read, so an honest
--! read never reaches it, and PostgreSQL computes a recursive query only as
--! far as its reader pulls rows, so the limit stops the recursion and not
--! only the output. A forged walk that hits it returns rows the client
--! refuses: it places them by the authenticated positions and child counts,
--! and refuses a repeated position (`j`). {{prefix}}.json_tree_children and
--! {{prefix}}.json_tree_child_count probe one level and never descend:
--! each ordinal's tag names at most one entry, and an entry carries one
--! parent tag, so the probes hit each entry at most once, and theirs is
--! `LIMIT` the entry count plus one, every entry and the miss.

--! @brief The children of the node whose token is `token`, as rows.
--!
--! What `jsonb_array_elements` is for an encrypted array, and the members of
--! an encrypted object: one row per child, in ordinal order, which puts an
--! array's elements in position order and an object's members in the random
--! order their ordinals were drawn in. A scalar or empty-container child
--! opens on its own; a child with children of its own opens with its
--! subtree. Enumerating one level needs no child's token, so the rows are
--! the same whichever rule each child's token takes.
--!
--! @param e public.{{prefix}}_json_search The stored document.
--! @param token text The node's token, base64: derived by the client from
--!        the node's path alone, and never stored.
--! @return SETOF public.{{prefix}}_json_entry The children, each with
--!         `d = 1`; no rows for a token that names no node, for a scalar or
--!         an empty container, and for the root of a document whose root is
--!         sealed, whose top-level fields chain from nothing.
CREATE FUNCTION {{prefix}}.json_tree_children(e public.{{prefix}}_json_search, token text)
  RETURNS SETOF public.{{prefix}}_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    -- The document, decompressed once (see "One decompression" above).
    raw AS MATERIALIZED (SELECT e::jsonb #> '{}'::text[] AS d),
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(raw.d ->> 'h') AS iv,
             raw.d -> 'sv' AS sv,
             idx.map,
             idx.nodes,
             {{prefix}}.json_tree_meta(raw.d) AS meta,
             jsonb_array_length(raw.d -> 'sv') AS entries,
             decode(token, 'base64') AS t
      FROM raw
      CROSS JOIN LATERAL {{prefix}}_internal.json_tree_index(raw.d) AS idx
    ),
    -- One row per ordinal probed under the node, from 0 to the first miss:
    -- `j` the position in `sv` of the entry found there, NULL at the miss.
    probe(o, j) AS (
        SELECT 0, (doc.map ->> {{prefix}}_internal.json_tree_parent_tag(doc.iv, doc.t, 0))::integer
        FROM doc
        WHERE doc.nodes ? {{prefix}}_internal.json_tree_self_tag(doc.iv, doc.t)
      UNION ALL
        SELECT p.o + 1, (doc.map ->> {{prefix}}_internal.json_tree_parent_tag(doc.iv, doc.t, p.o + 1))::integer
        FROM probe AS p, doc
        WHERE p.j IS NOT NULL
    ),
    -- At most one row per entry and the miss (see "The bound" above).
    visited AS MATERIALIZED (
      SELECT p.* FROM probe AS p LIMIT (SELECT doc.entries + 1 FROM doc)
    )
  SELECT (doc.meta || (doc.sv -> p.j) || jsonb_build_object('j', p.j, 'd', 1))::public.{{prefix}}_json_entry
  FROM visited AS p, doc
  WHERE p.j IS NOT NULL
  ORDER BY p.o
$$;

--! @brief How many children the node whose token is `token` has: the length
--!        of an encrypted array, or the member count of an object.
--!
--! The same probes as {{prefix}}.json_tree_children, counted: the index is
--! built once, where calling that function after finding the node would
--! build it twice.
--!
--! @param e public.{{prefix}}_json_search The stored document.
--! @param token text The node's token, base64.
--! @return integer The count; `0` for a scalar or an empty container; NULL
--!         for a token that names no node, as `jsonb_array_length` of a
--!         missing path is, and for the root of a document whose root is
--!         sealed, whose top-level fields chain from nothing and so cannot
--!         be counted from its token.
CREATE FUNCTION {{prefix}}.json_tree_child_count(e public.{{prefix}}_json_search, token text)
  RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    -- The document, decompressed once (see "One decompression" above).
    raw AS MATERIALIZED (SELECT e::jsonb #> '{}'::text[] AS d),
    doc AS MATERIALIZED (
      SELECT src.iv,
             idx.map,
             -- The position of the node the token names; NULL for none.
             (idx.nodes ->> {{prefix}}_internal.json_tree_self_tag(src.iv, src.t))::integer AS node,
             jsonb_array_length(src.d -> 'sv') AS entries,
             {{prefix}}_internal.json_tree_sealed_root(src.d ->> 'h') AS sealed,
             src.t
      FROM (SELECT raw.d,
                   {{prefix}}_internal.json_tree_iv(raw.d ->> 'h') AS iv,
                   decode(token, 'base64') AS t
            FROM raw) AS src
      CROSS JOIN LATERAL {{prefix}}_internal.json_tree_index(src.d) AS idx
    ),
    probe(o, j) AS (
        SELECT 0, (doc.map ->> {{prefix}}_internal.json_tree_parent_tag(doc.iv, doc.t, 0))::integer
        FROM doc
        WHERE doc.node IS NOT NULL AND NOT (doc.node = 0 AND doc.sealed)
      UNION ALL
        SELECT p.o + 1, (doc.map ->> {{prefix}}_internal.json_tree_parent_tag(doc.iv, doc.t, p.o + 1))::integer
        FROM probe AS p, doc
        WHERE p.j IS NOT NULL
    ),
    visited AS MATERIALIZED (
      SELECT p.* FROM probe AS p LIMIT (SELECT doc.entries + 1 FROM doc)
    )
  SELECT CASE
    WHEN doc.node IS NULL THEN NULL
    WHEN doc.node = 0 AND doc.sealed THEN NULL
    ELSE (SELECT count(*)::integer FROM visited AS p WHERE p.j IS NOT NULL)
  END
  FROM doc
$$;

--! @brief The nodes the tokens name, each with everything beneath it, as
--!        rows: the subtree read, in core SQL.
--!
--! For each token in turn, the entry whose self tag is the token's, at
--! `d = 0`, then its descendants, each with `d` its depth below that entry,
--! found by probing the ordinals under each node in hand until the first
--! miss and recursing under each hit's own token. So a read returns the
--! node it names, and `{}`, `[]`, a scalar and an absent node are an empty
--! object's entry, an empty array's entry, the scalar's entry and no rows,
--! the four answers `jsonb #>` gives. Rows come out in no promised order:
--! the client places each one by its tags and checks it under its parent's
--! digest, so the order they arrive in carries nothing. A token that names
--! no node yields no row, and nothing in a row is linkable to anything without its token.
--! The client sends one token for a path with no wildcard, and for a
--! wildcard one per position below its bound and a probe at the bound. The
--! server treats a probe like any other token, but can pick it out: it is
--! the last token of its level, the token count gives the bound away, and
--! a hit on it carries the element's selector rather than the leaf's.
--! Wanting a whole array is a read of the array's path, which sends the
--! array's own token.
--!
--! **The budget.** A read returns about two hundred characters per entry,
--! where a sealed root holds the whole document in one ciphertext of about
--! the plaintext's size. So when the root is sealed and the read would
--! return more than `budget` rows, counted across all the tokens and the
--! nodes at `d = 0` included, it stops and returns the root entry alone,
--! with `d = 0`: the client opens it to the whole document and evaluates
--! the same paths over it, which is cheaper on both sides than the read
--! past that point. The default of 64 is past the crossover by bytes
--! (about a dozen entries) by a margin that keeps a small subtree arriving
--! as the entries it is. A `budget` of `0` never falls back. Tokens that
--! name no node yield no row under any budget, and a document whose root
--! is not sealed is always read in full, since its root holds no document
--! to return.
--!
--! @param e public.{{prefix}}_json_search The stored document.
--! @param tokens text[] The tokens of the nodes to read, base64, each
--!        derived by the client from a concrete path alone.
--! @param budget integer The most rows to return before falling back to
--!        the sealed root; `0` to always read in full. Default 64.
--! @return SETOF public.{{prefix}}_json_entry The rows, each with its
--!         depth `d` below the node its token named; or the root entry
--!         alone, with `j = 0` and `d = 0`, past the budget.
CREATE FUNCTION {{prefix}}.json_tree_subtree(e public.{{prefix}}_json_search, tokens text[], budget integer DEFAULT 64)
  RETURNS SETOF public.{{prefix}}_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  WITH RECURSIVE
    -- The document, decompressed once (see "One decompression" above).
    raw AS MATERIALIZED (SELECT e::jsonb #> '{}'::text[] AS d),
    doc AS MATERIALIZED (
      SELECT {{prefix}}_internal.json_tree_iv(raw.d ->> 'h') AS iv,
             raw.d -> 'sv' AS sv,
             idx.map,
             idx.nodes,
             {{prefix}}.json_tree_meta(raw.d) AS meta,
             jsonb_array_length(raw.d -> 'sv') AS entries,
             budget > 0 AND {{prefix}}_internal.json_tree_sealed_root(raw.d ->> 'h') AS capped
      FROM raw
      CROSS JOIN LATERAL {{prefix}}_internal.json_tree_index(raw.d) AS idx
    ),
    -- One row per node found: `k` the place in `tokens` of the token whose
    -- node it sits in, `depth` its depth below that node, `pt` and `o`
    -- where a hit sits, its parent's token and its ordinal (NULL for the
    -- node a token named), `j` its position in `sv` and `entry` the entry
    -- there, and `t` the token the node was named by, NULL for a hit: a
    -- hit's own token is derived where it is used, in the probe beneath it
    -- (see "Inlining" above).
    walk(k, depth, pt, o, j, entry, t) AS (
        SELECT given.k, 0, NULL::bytea, NULL::integer, node.j, doc.sv -> node.j, given.t
        FROM doc
        CROSS JOIN LATERAL (
          SELECT g.ord AS k, decode(g.token, 'base64') AS t
          FROM unnest(tokens) WITH ORDINALITY AS g(token, ord)
        ) AS given
        CROSS JOIN LATERAL (
          SELECT (doc.nodes ->> {{prefix}}_internal.json_tree_self_tag(doc.iv, given.t))::integer AS j
        ) AS node
        WHERE node.j IS NOT NULL
      UNION ALL
        SELECT w.k, probe.depth, probe.pt, probe.o, pos.j, doc.sv -> pos.j, NULL::bytea
        FROM walk AS w
        CROSS JOIN doc
        CROSS JOIN LATERAL (
          -- Down: the first ordinal under this node, by its token: the one
          -- it was named by, else the one its own `s` and `x` derive. A hit
          -- whose self tag matches neither rule has no token, and is
          -- returned but not descended into.
          SELECT w.depth + 1 AS depth, own.t AS pt, 0 AS o
          FROM (
            SELECT COALESCE(w.t, {{prefix}}_internal.json_tree_hit_token(
                     doc.iv, w.pt, decode(w.entry ->> 's', 'base64'), w.o, w.entry ->> 'x')) AS t
          ) AS own
          WHERE own.t IS NOT NULL
          UNION ALL
          -- Across: the next ordinal under the same parent, from any hit,
          -- since a hit with no token of its own still has siblings.
          SELECT w.depth, w.pt, w.o + 1
          WHERE w.depth > 0
        ) AS probe
        CROSS JOIN LATERAL (
          SELECT (doc.map ->> {{prefix}}_internal.json_tree_parent_tag(doc.iv, probe.pt, probe.o))::integer AS j
        ) AS pos
        WHERE pos.j IS NOT NULL
    ),
    -- At most one row per entry for each token (see "The bound" above),
    -- whatever the budget: a budget of 0, or an open root, leaves `found`
    -- uncapped, and this is then the read's only limit.
    visited AS MATERIALIZED (
      SELECT w.* FROM walk AS w
      LIMIT (SELECT doc.entries * COALESCE(cardinality(tokens), 0) FROM doc)
    ),
    -- One row past the budget is enough to know the read went over; a read
    -- under it is complete. Uncapped, the limit is NULL: all that
    -- `visited` holds.
    found AS MATERIALIZED (
      SELECT w.k, w.depth, w.j, w.entry
      FROM visited AS w
      LIMIT (SELECT CASE WHEN doc.capped THEN budget + 1 END FROM doc)
    ),
    over AS MATERIALIZED (
      SELECT doc.capped AND (SELECT count(*) FROM found) > budget AS fallback FROM doc
    )
  SELECT rows.entry
  FROM (
    SELECT 0::bigint AS k, 0 AS j,
           (doc.meta || (doc.sv -> 0) || '{"j": 0, "d": 0}'::jsonb)::public.{{prefix}}_json_entry AS entry
    FROM doc, over
    WHERE over.fallback
    UNION ALL
    SELECT f.k, f.j,
           (doc.meta || f.entry || jsonb_build_object('j', f.j, 'd', f.depth))::public.{{prefix}}_json_entry
    FROM found AS f, doc, over
    WHERE NOT over.fallback
  ) AS rows
  ORDER BY rows.k, rows.j
$$;

------------------------------------------------------------------------------
-- Ordering at a path
------------------------------------------------------------------------------

--! @brief The path selector of an entry.
--! @param entry public.{{prefix}}_json_entry The entry.
--! @return text Its `s`, base64.
CREATE FUNCTION {{prefix}}.selector(entry public.{{prefix}}_json_entry)
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
--! @param entry public.{{prefix}}_json_entry The entry.
--! @return {{prefix}}_internal.ope_cllw The term, or NULL.
CREATE FUNCTION {{prefix}}.ord_term(entry public.{{prefix}}_json_entry)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_ope_cllw(entry::jsonb)
$$;

--! @brief The leaf ordering term of an ordering operand.
--! @param q {{prefix}}.query_json_leaf The operand.
--! @return {{prefix}}_internal.ope_cllw Its `op`, base64-decoded.
CREATE FUNCTION {{prefix}}.ord_term(q {{prefix}}.query_json_leaf)
  RETURNS {{prefix}}_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.json_tree_ope_cllw(q::jsonb)
$$;

--! @brief The path selector of an ordering operand: what `->` takes to reach
--!        the leaf the operand compares against.
--! @param q {{prefix}}.query_json_leaf The operand.
--! @return text Its `s`, base64.
CREATE FUNCTION {{prefix}}.selector(q {{prefix}}.query_json_leaf)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT q ->> 's'
$$;
