-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/types.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql

--! @file v3/json/functions.sql
--! @brief Extractors, containment engine, and path/array functions for the
--!        eql_v3 encrypted-JSONB (SteVec) surface.
--!
--! `selector` parameters here are *encrypted-side* selector hashes — the
--! deterministic hash the crypto layer emits in the `s` field of each sv
--! element. Plaintext JSONPaths are never accepted at runtime.

------------------------------------------------------------------------------
-- Envelope helpers (eql_v3 owns these; jsonb-only)
------------------------------------------------------------------------------

--! @brief Extract envelope metadata (i, v, h) from a raw jsonb encrypted value.
--!
--! `h` is the document's key header — hoisted once to the envelope because
--! every sv entry encrypts under the document's single data key. Grafting it
--! here (the same `meta_data(val) || entry` concat that already grafts `i`/`v`)
--! is what keeps an extracted `public.eql_v3_json_entry` self-contained
--! decryptable: decryption needs the header plus the entry's own `s` (the
--! nonce source) and `c` (the raw AEAD output). `jsonb_strip_nulls` drops the
--! keys entirely on payloads that lack them (e.g. a raw scalar envelope has
--! no `h`), rather than grafting JSON nulls.
--!
--! @param val jsonb encrypted EQL payload
--! @return jsonb Metadata object with `i`, `v`, and (for documents) `h`.
CREATE FUNCTION eql_v3.meta_data(val jsonb)
  RETURNS jsonb
  IMMUTABLE STRICT PARALLEL SAFE
  LANGUAGE SQL
AS $$
  SELECT jsonb_strip_nulls(
    jsonb_build_object('i', val->'i', 'v', val->'v', 'h', val->'h')
  );
$$;

COMMENT ON FUNCTION eql_v3.meta_data(jsonb) IS
  'eql-inline-critical: raw-jsonb envelope helper used by v3 jsonb wrappers; must stay inlinable (unpinned search_path)';

--! @brief Extract ciphertext (c) from a raw jsonb encrypted value.
--! @param val jsonb encrypted EQL payload
--! @return text The `c` field verbatim (base85 text).
--! @throws Exception if `c` is absent.
--! @note On the SteVec surface an entry's `c` is raw AEAD output and is NOT
--!       decryptable on its own: the decryption unit is the entry — its `s`
--!       (nonce source), `c`, and the document key header `h` (grafted onto
--!       extracted entries by `->`; see eql_v3.meta_data). Scalar payloads'
--!       `c` remains a self-describing encrypted record.
CREATE FUNCTION eql_v3.ciphertext(val jsonb)
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF val ? 'c' THEN
      RETURN val->>'c';
    END IF;
    RAISE 'Expected a ciphertext (c) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------------------------
-- Selector extractors
------------------------------------------------------------------------------

--! @brief Extract selector (s) from a raw jsonb encrypted value.
--! @param val jsonb encrypted EQL payload
--! @return text The selector value.
--! @throws Exception if `s` is absent.
CREATE FUNCTION eql_v3.selector(val jsonb)
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF val ? 's' THEN
      RETURN val->>'s';
    END IF;
    RAISE 'Expected a selector index (s) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract selector (s) from a ste_vec entry. The DOMAIN CHECK
--!        guarantees `s` is present, so this is a simple field access.
--! @param entry public.eql_v3_json_entry
--! @return text The selector value.
CREATE FUNCTION eql_v3.selector(entry public.eql_v3_json_entry)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 's'
$$;

------------------------------------------------------------------------------
-- Raw OPE-term extractor
------------------------------------------------------------------------------

--! @brief Low-level deterministic OPE byte extractor for a json entry.
--!
--! Returns the bytea of the entry's deterministic `op` (CLLW OPE) term, or NULL
--! for a term-less entry (a value entry, or a bool/null/structural path entry —
--! which carry no term because exact matching there is selector presence, not a
--! per-entry term). Entry-to-entry `=` / `<>` are blocked: these bytes are an
--! ordering encoding, not an exact equality representation.
--!
--! `op` is deterministic (equal plaintext at a fixed selector ⇒ equal bytes),
--! so byte equality on it is a sound equality for number/string leaves — with
--! the same encoding caveat as the scalar `_ord` surface (f64 rounding, string
--! collation make it lossy for `bigint`/`numeric`/`text`). Exact, loss-free
--! equality on a JSON field is selector presence (containment / the value
--! selector), not this term. This extractor remains available only for callers
--! that deliberately need encoded OPE-equivalence buckets. `hm` is retired —
--! entries no longer carry it.
--!
--! @param entry public.eql_v3_json_entry
--! @return bytea Decoded `op` bytes (NULL if the entry has no `op`, or is NULL).
CREATE FUNCTION eql_v3.ope_term(entry public.eql_v3_json_entry)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT decode(entry ->> 'op', 'hex')
$$;

--! @brief Deprecated compatibility alias for eql_v3.ope_term(json_entry).
--! @deprecated Use eql_v3.ope_term for raw OPE-equivalence inspection, or
--!             eql_v3.ord_term for ordered comparisons. This term is not an
--!             exact equality representation.
--! @param entry public.eql_v3_json_entry
--! @return bytea Decoded `op` bytes (NULL when the entry has no `op`).
CREATE FUNCTION eql_v3.eq_term(entry public.eql_v3_json_entry)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ope_term(entry)
$$;

COMMENT ON FUNCTION eql_v3.eq_term(public.eql_v3_json_entry) IS
  'DEPRECATED: use eql_v3.ope_term(json_entry); OPE bytes are not exact equality terms';

------------------------------------------------------------------------------
-- CLLW OPE per-entry overload (converged with the scalar ord_term)
------------------------------------------------------------------------------

--! @brief Extract the CLLW OPE index term from a ste_vec entry.
--!
--! An sv-element `op` term is only ever present on an sv element, never at a
--! root encrypted value, so the typed overload accepts public.eql_v3_json_entry —
--! the jsonb_entry twin of the generated scalar `eql_v3.ord_term`
--! extractors. Returns SQL NULL when `op` is absent (the strict `->>` /
--! `decode` chain propagates it), so btree NULL-filters such rows from range
--! queries. The returned eql_v3_internal.ope_cllw is a bytea domain: it orders
--! under native byte comparison with the DEFAULT btree opclass, so a
--! functional index on `eql_v3.ord_term(col -> 'selector')` engages
--! structurally with no custom operator class (Supabase/managed-Postgres
--! safe).
--!
--! @param entry public.eql_v3_json_entry
--! @return eql_v3_internal.ope_cllw Hex-decoded CLLW OPE term, or NULL when
--!         `op` is absent.
CREATE FUNCTION eql_v3.ord_term(entry public.eql_v3_json_entry)
  RETURNS eql_v3_internal.ope_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.ope_cllw(entry::jsonb)
$$;

------------------------------------------------------------------------------
-- sv-array helpers
------------------------------------------------------------------------------

--! @brief Extract the sv element array as raw jsonb[].
--!
--! Returns the elements of `sv` (or a single-element array wrapping the value
--! when there is no `sv`). No envelope re-wrapping — raw jsonb elements.
--!
--! @param val jsonb encrypted EQL payload
--! @return jsonb[] Array of sv elements.
CREATE FUNCTION eql_v3.ste_vec(val jsonb)
  RETURNS jsonb[]
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv jsonb;
    ary jsonb[];
  BEGIN
    IF val ? 'sv' THEN
      sv := val->'sv';
    ELSE
      sv := jsonb_build_array(val);
    END IF;

    SELECT array_agg(elem)
      INTO ary
      FROM jsonb_array_elements(sv) AS elem;

    RETURN ary;
  END;
$$ LANGUAGE plpgsql;

--! @brief Check if a jsonb payload is marked as an sv array (`a` flag true).
--! @param val jsonb encrypted EQL payload
--! @return boolean True if `a` is present and true.
CREATE FUNCTION eql_v3_internal.is_ste_vec_array(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF val ? 'a' THEN
      RETURN (val->>'a')::boolean;
    END IF;
    RETURN false;
  END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------------------------
-- Deterministic-fields array for GIN containment
------------------------------------------------------------------------------

--! @brief Extract deterministic containment fields (s) per sv element.
--!
--! Excludes non-deterministic ciphertext so PostgreSQL's native jsonb `@>` can
--! compare for containment. Use for GIN indexes and containment queries.
--! Exact and structural containment are selector-set containment, so ordering
--! terms are deliberately excluded.
--!
--! @param val jsonb encrypted EQL payload
--! @return jsonb[] Array of objects with only deterministic fields.
CREATE FUNCTION eql_v3.jsonb_array(val jsonb)
RETURNS jsonb[]
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT ARRAY(
    SELECT jsonb_object_agg(kv.key, kv.value)
    FROM jsonb_array_elements(
      CASE WHEN val ? 'sv' THEN val->'sv' ELSE jsonb_build_array(val) END
    ) AS elem,
    LATERAL jsonb_each(elem) AS kv(key, value)
    WHERE kv.key = 's'
    GROUP BY elem
  );
$$;

COMMENT ON FUNCTION eql_v3.jsonb_array(jsonb) IS
  'eql-inline-critical: raw-jsonb deterministic-field array helper; must stay inlinable (unpinned search_path)';

------------------------------------------------------------------------------
-- Containment
------------------------------------------------------------------------------

--! @brief GIN-indexable containment check: does `a` contain all of `b`?
--! @param a jsonb Container payload.
--! @param b jsonb Search payload.
--! @return boolean True if a contains all deterministic elements of b.
--! @note Public raw-`jsonb[]` containment helper over the extracted
--!       deterministic fields — the function-form entrypoint for containment on
--!       platforms without operator support (Supabase/PostgREST). The typed
--!       `public.eql_v3_json_search` `@>` operator does NOT call this function — it binds to
--!       `eql_v3.jsonb_document_contains` instead — but both agree on the result (a
--!       parity test pins this). Also the documented GIN index expression
--!       (`eql_v3.jsonb_array(col)`); see docs/reference/database-indexes.md.
CREATE FUNCTION eql_v3.jsonb_contains(a jsonb, b jsonb)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v3.jsonb_array(a) @> eql_v3.jsonb_array(b);
$$;

COMMENT ON FUNCTION eql_v3.jsonb_contains(jsonb, jsonb) IS
  'eql-inline-critical: raw-jsonb containment helper; must stay inlinable (unpinned search_path)';

--! @brief GIN-indexable "is contained by" check.
--! @param a jsonb Payload to check.
--! @param b jsonb Container payload.
--! @return boolean True if all elements of a are contained in b.
--! @note Public raw-`jsonb[]` reverse-containment helper — the function-form
--!       entrypoint for `<@` on platforms without operator support. The typed
--!       `public.eql_v3_json_search` `<@` operator binds to `eql_v3.jsonb_document_contains` instead,
--!       but both agree on the result.
CREATE FUNCTION eql_v3.jsonb_contained_by(a jsonb, b jsonb)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v3.jsonb_array(a) <@ eql_v3.jsonb_array(b);
$$;

COMMENT ON FUNCTION eql_v3.jsonb_contained_by(jsonb, jsonb) IS
  'eql-inline-critical: raw-jsonb contained-by helper; must stay inlinable (unpinned search_path)';

--! @brief Check if an sv array contains a specific sv element.
--!
--! Match = **selector equal**. Containment reduces to selector-set subset
--! testing: a leaf's value is tokenized into its **value selector**
--! (`SEL(tag ‖ path ‖ value)`), so the presence of a needle's value selector
--! in the stored `sv` IS the exact value match — a keyed-MAC comparison,
--! injective per (path, value), immune to the ordering encoding's losses
--! (f64 rounding, string collation). Structural containment rides the same
--! test: a needle's path selector (`SEL(path)`, value-independent) matches any
--! stored node at that path, and the needle's value selectors constrain the
--! values. No per-entry term comparison is involved — the value is in the
--! selector, not in a term.
--!
--! @param a jsonb[] sv array to search within.
--! @param b jsonb sv element to search for.
--! @return boolean True if b's selector is present in any element of a.
CREATE FUNCTION eql_v3.jsonb_document_contains(a jsonb[], b jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    result boolean;
    _a jsonb;
  BEGIN
    result := false;

    FOR idx IN 1..array_length(a, 1) LOOP
      _a := a[idx];
      result := result OR (eql_v3.selector(_a) = eql_v3.selector(b));
      EXIT WHEN result;
    END LOOP;

    RETURN result;
  END;
$$ LANGUAGE plpgsql;

--! @brief Does encrypted value `a` contain all sv elements of `b`?
--!
--! Empty b is always contained. Each element of b must have its selector
--! present in some element of a (selector-subset containment).
--!
--! @param a public.eql_v3_json_search Container.
--! @param b public.eql_v3_json_search Elements to find.
--! @return boolean True if all elements of b are contained in a.
--! @see eql_v3.jsonb_document_contains(jsonb[], jsonb)
CREATE FUNCTION eql_v3.jsonb_document_contains(a public.eql_v3_json_search, b public.eql_v3_json_search)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.to_ste_vec_query(a)::jsonb
       @> eql_v3.to_ste_vec_query(b)::jsonb
$$;

------------------------------------------------------------------------------
-- Path queries (text selector only)
------------------------------------------------------------------------------

--! @brief Query encrypted JSONB for sv elements matching `selector`.
--!
--! Returns one jsonb_entry row per matching encrypted element. Returns empty
--! set on no match. It deliberately does not wrap multiple matches as an
--! public.eql_v3_json_search document, because the root document domain requires an `sv`
--! array and single leaves belong to public.eql_v3_json_entry.
--!
--! @param val jsonb encrypted EQL payload with `sv`.
--! @param selector text Selector hash (`s` value).
--! @return SETOF public.eql_v3_json_entry Matching encrypted entries.
--! @see eql_v3.jsonb_path_query_first
CREATE FUNCTION eql_v3.jsonb_path_query(val jsonb, selector text)
  RETURNS SETOF public.eql_v3_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (eql_v3.meta_data(val) || elem)::public.eql_v3_json_entry
  FROM jsonb_array_elements(val -> 'sv') elem
  WHERE elem ->> 's' = selector
$$;

COMMENT ON FUNCTION eql_v3.jsonb_path_query(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path query helper; must stay inlinable (unpinned search_path)';

--! @brief Check if a selector path exists in encrypted JSONB.
--! @param val jsonb encrypted EQL payload.
--! @param selector text Selector hash to test.
--! @return boolean True if a matching element exists.
CREATE FUNCTION eql_v3.jsonb_path_exists(val jsonb, selector text)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM jsonb_array_elements(val -> 'sv') elem
    WHERE elem ->> 's' = selector
  );
$$;

COMMENT ON FUNCTION eql_v3.jsonb_path_exists(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path exists helper; must stay inlinable (unpinned search_path)';

--! @brief Get the first sv element matching `selector`, or NULL.
--! @param val jsonb encrypted EQL payload.
--! @param selector text Selector hash to match.
--! @return public.eql_v3_json_entry First matching element or NULL.
CREATE FUNCTION eql_v3.jsonb_path_query_first(val jsonb, selector text)
  RETURNS public.eql_v3_json_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (eql_v3.meta_data(val) || elem)::public.eql_v3_json_entry
  FROM jsonb_array_elements(val -> 'sv') elem
  WHERE elem ->> 's' = selector
  LIMIT 1
$$;

COMMENT ON FUNCTION eql_v3.jsonb_path_query_first(jsonb, text) IS
  'eql-inline-critical: raw-jsonb path first helper; must stay inlinable (unpinned search_path)';

------------------------------------------------------------------------------
-- Array functions
------------------------------------------------------------------------------

--! @brief Get the length of an encrypted JSONB array.
--! @param val jsonb encrypted EQL payload (must have `a` flag true).
--! @return integer Number of elements.
--! @throws Exception 'cannot get array length of a non-array' if not an array.
CREATE FUNCTION eql_v3.jsonb_array_length(val jsonb)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv jsonb[];
  BEGIN
    IF eql_v3_internal.is_ste_vec_array(val) THEN
      sv := eql_v3.ste_vec(val);
      RETURN array_length(sv, 1);
    END IF;

    RAISE 'cannot get array length of a non-array';
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract elements of an encrypted JSONB array as rows.
--! @param val jsonb encrypted EQL payload (must have `a` flag true).
--! @return SETOF public.eql_v3_json_entry One row per element (metadata preserved).
--! @throws Exception 'cannot extract elements from non-array' if not an array.
CREATE FUNCTION eql_v3.jsonb_array_elements(val jsonb)
  RETURNS SETOF public.eql_v3_json_entry
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv jsonb[];
    meta jsonb;
    item jsonb;
  BEGIN
    IF NOT eql_v3_internal.is_ste_vec_array(val) THEN
      RAISE 'cannot extract elements from non-array';
    END IF;

    meta := eql_v3.meta_data(val);
    sv := eql_v3.ste_vec(val);

    FOR idx IN 1..array_length(sv, 1) LOOP
      item = sv[idx];
      RETURN NEXT (meta || item)::public.eql_v3_json_entry;
    END LOOP;

    RETURN;
  END;
$$ LANGUAGE plpgsql;

-- NOTE: `eql_v3.jsonb_array_elements_text` (SETOF bare per-element ciphertext
-- text) was removed with the envelope wire format: an sv entry's `c` is raw
-- AEAD output whose nonce derives from the entry's `s`, so a bare ciphertext
-- stream is not decryptable and the function had no remaining correct use.
-- Use `eql_v3.jsonb_array_elements` — its entry rows carry `s`, `c`, and the
-- grafted document key header `h`, the complete decryption unit.
