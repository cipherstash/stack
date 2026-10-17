-- ============================================================================
-- Prototype A: plaintext-selector simulation of SteVec containment (no crypto).
-- Selectors are the canonical strings a keyed PRF would MAC; containment
-- semantics are identical because the PRF is injective in practice.
-- ============================================================================
CREATE SCHEMA sim;

-- Flatten a jsonb document into merged entries {s, vs, n?, g?}.
--   s  = wildcard path selector            ("$.a[*].x")
--   vs = value selector = s | tag | canon  ("$.a[*].x|NUM|1")
--   n  = this node's element tag (array elements only; positional, per column)
--   g  = innermost enclosing array element's tag (descendants of an element)
CREATE FUNCTION sim.flatten(doc jsonb, path text DEFAULT '$', elem text DEFAULT NULL, pos text DEFAULT '$')
RETURNS SETOF jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  tag text; canon text; k text; v jsonb; i int := 0; own text := NULL; e jsonb;
BEGIN
  tag := CASE jsonb_typeof(doc) WHEN 'object' THEN 'MAP' WHEN 'array' THEN 'ARRY'
           WHEN 'string' THEN 'STR' WHEN 'number' THEN 'NUM' WHEN 'boolean' THEN upper(doc::text) ELSE 'NULL' END;
  canon := CASE jsonb_typeof(doc) WHEN 'string' THEN doc #>> '{}' WHEN 'number' THEN (doc::numeric)::text ELSE '' END;
  e := jsonb_build_object('s', path, 'vs', path || '|' || tag || '|' || canon);
  IF elem IS NOT NULL THEN e := e || jsonb_build_object('g', elem); END IF;
  IF right(path, 3) = '[*]' THEN own := 'E:' || pos; e := e || jsonb_build_object('n', own); END IF;
  RETURN NEXT e;
  IF jsonb_typeof(doc) = 'object' THEN
    FOR k, v IN SELECT * FROM jsonb_each(doc) ORDER BY 1 LOOP
      RETURN QUERY SELECT * FROM sim.flatten(v, path || '.' || k, COALESCE(own, elem), pos || '.' || k);
    END LOOP;
  ELSIF jsonb_typeof(doc) = 'array' THEN
    FOR v IN SELECT * FROM jsonb_array_elements(doc) LOOP
      RETURN QUERY SELECT * FROM sim.flatten(v, path || '[*]', COALESCE(own, elem), pos || '[' || i || ']');
      i := i + 1;
    END LOOP;
  END IF;
END $$;

CREATE FUNCTION sim.store(doc jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('sv', jsonb_agg(e)) FROM sim.flatten(doc) e $$;

-- The flat needle: every selector of the needle, as today (s and vs only).
CREATE FUNCTION sim.flat_query(doc jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('sv', jsonb_agg(jsonb_build_object('s', e->'s') ) || jsonb_agg(jsonb_build_object('vs', e->'vs')))
  FROM sim.flatten(doc) e $$;

-- What GIN indexes: {s, vs} per entry, nothing else.
CREATE FUNCTION sim.to_query(stored jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('sv', jsonb_agg(jsonb_build_object('s', e->'s', 'vs', e->'vs')))
  FROM jsonb_array_elements(stored->'sv') e $$;

-- Flat containment = today's semantics.
CREATE FUNCTION sim.flat_contains(stored jsonb, needle jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT sim.to_query(stored) @> sim.flat_query(needle) $$;

-- Group structure of a needle: one group per array ELEMENT that is a container,
-- {at: wildcard path of the element, need: [vs...] (constraints inside the element
-- but outside nested array elements, including the element's own vs), sub: [groups]}
CREATE FUNCTION sim.groups(doc jsonb, path text DEFAULT '$', in_elem boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE out jsonb := '[]'; k text; v jsonb; g jsonb;
BEGIN
  IF jsonb_typeof(doc) = 'object' THEN
    FOR k, v IN SELECT * FROM jsonb_each(doc) LOOP out := out || sim.groups(v, path || '.' || k, in_elem); END LOOP;
  ELSIF jsonb_typeof(doc) = 'array' THEN
    FOR v IN SELECT * FROM jsonb_array_elements(doc) LOOP
      IF jsonb_typeof(v) IN ('object','array') THEN
        -- a container element: a group of everything inside it, down to nested elements
        g := jsonb_build_object('at', path || '[*]',
               'need', (SELECT COALESCE(jsonb_agg(e->'vs'), '[]') FROM sim.flatten(v, path || '[*]') e WHERE NOT (e ? 'g') OR e->>'g' = 'E:$'),
               'sub', sim.groups(v, path || '[*]', true));
        out := out || jsonb_build_array(g);
      END IF;
    END LOOP;
  END IF;
  RETURN out;
END $$;

-- Exact recheck: for every group there is a stored element whose own entries
-- carry every needed selector, and whose nested elements satisfy the sub-groups.
CREATE FUNCTION sim.groups_ok(sv jsonb, grps jsonb, parent_tag text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE grp jsonb; ok boolean; el jsonb;
BEGIN
  FOR grp IN SELECT * FROM jsonb_array_elements(grps) LOOP
    ok := false;
    FOR el IN SELECT e FROM jsonb_array_elements(sv) e
              WHERE e ? 'n' AND e->>'s' = grp->>'at'
                AND (parent_tag IS NULL OR e->>'g' = parent_tag) LOOP
      -- every needed selector is on an entry of this element (its own entry or a descendant outside nested elements)
      IF NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements_text(grp->'need') need
           WHERE NOT EXISTS (
             SELECT 1 FROM jsonb_array_elements(sv) x
             WHERE x->>'vs' = need AND (x->>'n' = el->>'n' OR (x->>'g' = el->>'n' AND NOT (x ? 'n'))
                                        OR (x ? 'n' AND x->>'g' = el->>'n' AND x->>'vs' = need)))) -- nested element's own vs (its MAP/ARRY tag) counts as inside the outer element
         AND sim.groups_ok(sv, grp->'sub', el->>'n') THEN
        ok := true; EXIT;
      END IF;
    END LOOP;
    IF NOT ok THEN RETURN false; END IF;
  END LOOP;
  RETURN true;
END $$;

CREATE FUNCTION sim.exact_contains(stored jsonb, needle jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT sim.flat_contains(stored, needle) AND sim.groups_ok(stored->'sv', sim.groups(needle)) $$;

-- Oracle: random-ish corpus; report every disagreement with jsonb @>.
CREATE TABLE sim.cases(stored jsonb, needle jsonb);
INSERT INTO sim.cases VALUES
 ('{"a":[{"x":1,"y":5},{"x":7,"y":2}]}', '{"a":[{"x":1,"y":2}]}'),
 ('{"a":[{"x":1,"y":2,"z":3}]}', '{"a":[{"x":1,"y":2}]}'),
 ('{"a":[{"x":1}]}', '{"a":[{"x":1},{"x":1}]}'),
 ('{"a":[{"b":[{"x":1},{"y":2}]}]}', '{"a":[{"b":[{"x":1,"y":2}]}]}'),
 ('{"a":[{"b":[{"x":1,"y":2}]}]}', '{"a":[{"b":[{"x":1,"y":2}]}]}'),
 ('{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}', '{"a":[{"b":[{"x":1,"y":2}],"c":4}]}'),
 ('{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}', '{"a":[{"b":[{"x":1,"y":2}],"c":3}]}'),
 ('{"a":[{"b":{"c":1,"d":2}},{"b":{"c":3,"d":2}}]}', '{"a":[{"b":{"c":1,"d":2}}]}'),
 ('{"a":[{"b":{"c":1,"d":5}},{"b":{"c":3,"d":2}}]}', '{"a":[{"b":{"c":1,"d":2}}]}'),
 ('{"a":[[1,2],[3,4]]}', '{"a":[[1,4]]}'),
 ('{"a":[[1,2],[3,4]]}', '{"a":[[1,2]]}'),
 ('{"a":[[1,2],[3,4]]}', '{"a":[[1],[4]]}'),
 ('{"a":[1,2]}', '{"a":[]}'),
 ('{"a":{"b":1}}', '{"a":{}}'),
 ('{"a":{}}', '{"a":{"b":1}}'),
 ('{"a":[1]}', '{"a":1}'),
 ('{"a":1}', '{"a":[1]}'),
 ('[1,[2]]', '[2]'),
 ('[1,[2]]', '[[2]]'),
 ('[1,2]', '[1,1,1]'),
 ('{"a":1}', '{}'),
 ('[1]', '{}'),
 ('{"a":null}', '{"a":null}'),
 ('{"a":"2"}', '{"a":2}'),
 ('{"a":2}', '{"a":2.0}'),
 ('["a"]', '"a"'),
 ('"a"', '"a"'),
 ('{"a":[{"x":1}]}', '{"a":[{}]}'),
 ('{"a":[1]}', '{"a":[{}]}'),
 ('{"a":[{"t":[{"u":1,"v":2}]},{"t":[{"u":1},{"v":2}]}]}', '{"a":[{"t":[{"u":1,"v":2}]}]}'),
 ('{"a":[{"t":[{"u":1},{"v":2}]}]}', '{"a":[{"t":[{"u":1,"v":2}]}]}');

SELECT stored::text AS stored, needle::text AS needle,
       (stored @> needle) AS jsonb,
       sim.flat_contains(stored, needle) AS flat_today,
       sim.exact_contains(stored, needle) AS exact_new,
       CASE WHEN (stored @> needle) <> sim.exact_contains(stored, needle) THEN '<<< DISAGREES' ELSE '' END AS verdict
FROM sim.cases;

-- Known simulation artefacts (not design defects):
--   * `2` vs `2.0`: this file canonicalises numbers with numeric::text, so they differ;
--     the real producer canonicalises by numeric value (cipherstash-client's
--     canonical_number does today), and the two agree.
--   * `["a"] @> '"a"'`: the top-level-scalar false negative is REAL in v3 today and
--     is fixed in the design by the needle's `alt` selector set, not here.
