-- ============================================================================
-- Prototype B: the token chain, server side, in core PostgreSQL only (sha256, bytea).
--   t(node)      = client secret token, 16 bytes. t(root) = PRF_idx("$") (simulated).
--   t(child)     = PRF(t(parent) || label)   (client only; label never leaves the client)
--   p(child)     = H(t(parent) || 'p')[..16]  -> stored: "who my parent is", unlinkable without t(parent)
--   w(child)     = t(child) XOR H(t(parent) || 'w' || c)[..16]  -> stored: wrapped token
--   c            = node-local ciphertext (simulated here as random-looking bytes)
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

-- Client-side simulation: flatten a doc into chained entries {s, p, w, c, lbl(debug only)}.
CREATE FUNCTION chain.flatten(doc jsonb, t bytea, path text, parent_t bytea, label text)
RETURNS SETOF jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k text; v jsonb; i int := 0; c bytea; e jsonb; ct bytea;
BEGIN
  -- simulated node-local ciphertext: Enc(label, kind, scalar) -> here just a hash so it is unique and public
  ct := sha256(('ct' || path || doc::text)::bytea);
  e := jsonb_build_object('s', path, 'c', encode(ct, 'hex'), 'lbl', label || '=' || CASE WHEN jsonb_typeof(doc) IN ('object','array') THEN jsonb_typeof(doc) ELSE doc::text END);
  IF parent_t IS NOT NULL THEN
    e := e || jsonb_build_object('p', encode(chain.h16(parent_t || 'p'::bytea), 'hex'),
                                 'w', encode(chain.xor16(t, chain.h16(parent_t || 'w'::bytea || ct)), 'hex'));
  END IF;
  RETURN NEXT e;
  IF jsonb_typeof(doc) = 'object' THEN
    FOR k, v IN SELECT * FROM jsonb_each(doc) ORDER BY 1 LOOP
      RETURN QUERY SELECT * FROM chain.flatten(v, chain.h16(t || ('.' || k)::bytea), path || '.' || k, t, k);
    END LOOP;
  ELSIF jsonb_typeof(doc) = 'array' THEN
    FOR v IN SELECT * FROM jsonb_array_elements(doc) LOOP
      RETURN QUERY SELECT * FROM chain.flatten(v, chain.h16(t || ('[' || i || ']')::bytea), path || '[*]', t, i::text);
      i := i + 1;
    END LOOP;
  END IF;
END $$;

CREATE FUNCTION chain.t_root() RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT chain.h16('idxkey:$'::bytea) $$;
-- the client derives a start token from a path by walking labels
CREATE FUNCTION chain.t_for(labels text[]) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE t bytea := chain.t_root(); l text;
BEGIN FOREACH l IN ARRAY labels LOOP t := chain.h16(t || l::bytea); END LOOP; RETURN t; END $$;

CREATE FUNCTION chain.store(doc jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('sv', jsonb_agg(e)) FROM chain.flatten(doc, chain.t_root(), '$', NULL, '$') e $$;

-- SERVER SIDE: subtree of the node whose token is t_start. Plain recursive CTE.
CREATE FUNCTION chain.subtree(stored jsonb, t_start bytea)
RETURNS TABLE(depth int, entry jsonb) LANGUAGE sql STABLE AS $$
  WITH RECURSIVE walk(depth, t, entry) AS (
      SELECT 0, t_start, NULL::jsonb
    UNION ALL
      SELECT w.depth + 1,
             chain.xor16(decode(e->>'w', 'hex'), chain.h16(w.t || 'w'::bytea || decode(e->>'c', 'hex'))),
             e
      FROM walk w
      JOIN LATERAL jsonb_array_elements(stored->'sv') e
        ON e->>'p' = encode(chain.h16(w.t || 'p'::bytea), 'hex')
  )
  SELECT depth, entry FROM walk WHERE entry IS NOT NULL
$$;

\set doc '{"hello":"world-1","nested":{"deep":"constant","list":[{"x":1},{"x":2}]},"number":1}'
SELECT jsonb_pretty(chain.store(:'doc'::jsonb));
-- subtree under $.nested (what `doc -> '$.nested'` must return), via the client-derived token
SELECT depth, entry->>'s' AS s, entry->>'lbl' AS decrypted_label_kind_value
FROM chain.subtree(chain.store(:'doc'::jsonb), chain.t_for(ARRAY['.nested'])) ORDER BY depth, s;
-- a wrong token unlocks nothing
SELECT count(*) AS entries_with_wrong_token FROM chain.subtree(chain.store(:'doc'::jsonb), chain.h16('garbage'::bytea));
-- whole document from the root token
SELECT count(*) AS entries_under_root, (SELECT jsonb_array_length(chain.store(:'doc'::jsonb)->'sv')) - 1 AS expected
FROM chain.subtree(chain.store(:'doc'::jsonb), chain.t_root());
