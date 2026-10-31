-- ============================================================================
-- Prototype B: the token chain, server side, in core PostgreSQL only (sha256, bytea).
-- The derivations are the plan's ("The token chain"), with H = SHA-256 truncated to
-- 16 bytes and the domain byte first:
--   t(root)  = PRF(json/token ‖ column, "$")[..16]           client only (simulated: a hash)
--   t(child) = H("t" ‖ t(parent) ‖ 0x01 ‖ key)               object member (client only)
--   t(child) = H("t" ‖ t(parent) ‖ 0x02 ‖ LE64(index))       array element (client only)
--   p(child) = H("p" ‖ iv ‖ t(parent))                       stored: unlinkable without t(parent)
--   w(child) = t(child) XOR H("w" ‖ iv ‖ t(parent) ‖ c)      stored: the wrapped token
--   c        = node-local ciphertext (simulated here as random-looking bytes)
-- iv is the document key's IV from the header `h`, simulated as the stored `iv` field.
-- This is the chain from the root (the sealed-root option off), so that the root
-- token can be shown to reach every non-root entry.
-- The server, given t(start), finds children by p, unwraps each child's token with
-- its own c as the mask input, and recurses. Nothing else in the row is linkable.
-- ============================================================================
CREATE SCHEMA chain;

CREATE FUNCTION chain.h16(x bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT substr(sha256(x), 1, 16) $$;
CREATE FUNCTION chain.xor16(a bytea, b bytea) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE r bytea := a; i int;
BEGIN
  FOR i IN 0..15 LOOP r := set_byte(r, i, get_byte(a, i) # get_byte(b, i)); END LOOP;
  RETURN r;
END $$;
CREATE FUNCTION chain.le64(n bigint) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE r bytea := '\x0000000000000000'; i int;
BEGIN
  FOR i IN 0..7 LOOP r := set_byte(r, i, ((n >> (8 * i)) & 255)::int); END LOOP;
  RETURN r;
END $$;

-- Client side: a child's token from its parent's and its label (a key or an index).
CREATE FUNCTION chain.child_token(t bytea, label jsonb) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE jsonb_typeof(label)
    WHEN 'string' THEN chain.h16('t'::bytea || t || '\x01'::bytea || convert_to(label #>> '{}', 'UTF8'))
    ELSE chain.h16('t'::bytea || t || '\x02'::bytea || chain.le64((label #>> '{}')::bigint))
  END $$;
CREATE FUNCTION chain.parent_tag(iv bytea, t bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
  SELECT chain.h16('p'::bytea || iv || t) $$;
CREATE FUNCTION chain.mask(iv bytea, t bytea, c bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
  SELECT chain.h16('w'::bytea || iv || t || c) $$;

-- Client-side simulation: flatten a doc into chained entries {s, p, w, c, lbl(debug only)}.
CREATE FUNCTION chain.flatten(doc jsonb, iv bytea, t bytea, path text, parent_t bytea, label text)
RETURNS SETOF jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k text; v jsonb; i int := 0; e jsonb; ct bytea;
BEGIN
  -- simulated node-local ciphertext: Enc(label, kind, scalar) -> here just a hash so it is unique and public
  ct := sha256(convert_to('ct' || path || label || doc::text, 'UTF8'));
  e := jsonb_build_object('s', path, 'c', encode(ct, 'hex'), 'lbl', label || '=' || CASE WHEN jsonb_typeof(doc) IN ('object','array') THEN jsonb_typeof(doc) ELSE doc::text END);
  IF parent_t IS NOT NULL THEN
    e := e || jsonb_build_object('p', encode(chain.parent_tag(iv, parent_t), 'hex'),
                                 'w', encode(chain.xor16(t, chain.mask(iv, parent_t, ct)), 'hex'));
  END IF;
  RETURN NEXT e;
  IF jsonb_typeof(doc) = 'object' THEN
    FOR k, v IN SELECT * FROM jsonb_each(doc) ORDER BY 1 LOOP
      RETURN QUERY SELECT * FROM chain.flatten(v, iv, chain.child_token(t, to_jsonb(k)), path || '.' || k, t, k);
    END LOOP;
  ELSIF jsonb_typeof(doc) = 'array' THEN
    FOR v IN SELECT * FROM jsonb_array_elements(doc) LOOP
      RETURN QUERY SELECT * FROM chain.flatten(v, iv, chain.child_token(t, to_jsonb(i)), path || '[*]', t, i::text);
      i := i + 1;
    END LOOP;
  END IF;
END $$;

CREATE FUNCTION chain.t_root() RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT chain.h16('idxkey:json/token:$'::bytea) $$;
-- the client derives a start token from a positional path: keys as strings, indexes as numbers
CREATE FUNCTION chain.t_for(steps jsonb) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE t bytea := chain.t_root(); step jsonb;
BEGIN FOR step IN SELECT * FROM jsonb_array_elements(steps) LOOP t := chain.child_token(t, step); END LOOP; RETURN t; END $$;

CREATE FUNCTION chain.store(doc jsonb, iv bytea) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('iv', encode(iv, 'hex'), 'sv', jsonb_agg(e))
  FROM chain.flatten(doc, iv, chain.t_root(), '$', NULL, '$') e $$;

-- SERVER SIDE: subtree of the node whose token is t_start. Plain recursive CTE.
CREATE FUNCTION chain.subtree(stored jsonb, t_start bytea)
RETURNS TABLE(depth int, entry jsonb) LANGUAGE sql STABLE AS $$
  WITH RECURSIVE walk(depth, t, entry) AS (
      SELECT 0, t_start, NULL::jsonb
    UNION ALL
      SELECT w.depth + 1,
             chain.xor16(decode(e->>'w', 'hex'), chain.mask(decode(stored->>'iv', 'hex'), w.t, decode(e->>'c', 'hex'))),
             e
      FROM walk w
      JOIN LATERAL jsonb_array_elements(stored->'sv') e
        ON e->>'p' = encode(chain.parent_tag(decode(stored->>'iv', 'hex'), w.t), 'hex')
  )
  SELECT depth, entry FROM walk WHERE entry IS NOT NULL
$$;

\set doc '{"hello":"world-1","nested":{"deep":"constant","list":[{"x":1},{"x":2}]},"number":1}'
\set iv '\'\\x000102030405060708090a0b0c0d0e0f\'::bytea'
SELECT jsonb_pretty(chain.store(:'doc'::jsonb, :iv));
-- subtree under $.nested (what `doc -> '$.nested'` must return), via the client-derived token
SELECT depth, entry->>'s' AS s, entry->>'lbl' AS decrypted_label_kind_value
FROM chain.subtree(chain.store(:'doc'::jsonb, :iv), chain.t_for('["nested"]')) ORDER BY depth, s;
-- a wrong token unlocks nothing
SELECT count(*) AS entries_with_wrong_token FROM chain.subtree(chain.store(:'doc'::jsonb, :iv), chain.h16('garbage'::bytea));
-- whole document from the root token
SELECT count(*) AS entries_under_root, (SELECT jsonb_array_length(chain.store(:'doc'::jsonb, :iv)->'sv')) - 1 AS expected
FROM chain.subtree(chain.store(:'doc'::jsonb, :iv), chain.t_root());
-- the same document under another IV: no parent tag in common, so shape does not link across rows at rest
SELECT count(*) AS parent_tags_shared_across_ivs
FROM jsonb_array_elements(chain.store(:'doc'::jsonb, :iv)->'sv') a
JOIN jsonb_array_elements(chain.store(:'doc'::jsonb, '\xff0102030405060708090a0b0c0d0e0f'::bytea)->'sv') b
  ON a->>'p' = b->>'p';
