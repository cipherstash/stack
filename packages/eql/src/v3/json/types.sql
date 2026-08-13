-- REQUIRE: src/v3/schema.sql

--! @file v3/json/types.sql
--! @brief Domain types for the eql_v3 encrypted-JSONB (SteVec) surface.
--!
--! Three jsonb-backed domains (none over another domain — operators resolve
--! against the ultimate base type jsonb, so the native-jsonb firewall in
--! blockers.sql can attach):
--!   - public.eql_v3_json_search     — storage/root: an EQL envelope object ({i, v, ...}).
--!   - public.eql_v3_json_entry — a single sv element (returned by `->`).
--!   - eql_v3.query_json  — a containment needle (sv elements, no ciphertext).

--! @brief Validate a single SteVec entry payload.
--! @internal
--! @param val jsonb Candidate entry payload.
--! @return boolean True when `val` is an sv entry with string `s`, string `c`,
--!         and — for an ordered (number/string) path entry only — a string
--!         `op` ordering term. Value entries (value-inclusive selectors) and
--!         non-orderable path entries (bool/null/object/array) are term-less
--!         `{s, c}`: exact matching is selector presence, so an entry carries
--!         no per-value equality term. `hm` is retired and must be absent —
--!         a stale `hm`-bearing payload fails loudly rather than degrading to
--!         a value-less entry. The optional document metadata `i`, `v`, and
--!         `h` is accepted because selector lookup grafts it onto the entry
--!         before casting to `public.eql_v3_json_entry`.
CREATE OR REPLACE FUNCTION public.eql_v3_is_valid_ste_vec_entry_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND jsonb_typeof(val -> 's') = 'string'
     AND jsonb_typeof(val -> 'c') = 'string'
     AND NOT (val ? 'hm')
     AND (NOT (val ? 'a') OR jsonb_typeof(val -> 'a') = 'boolean')
     AND (NOT (val ? 'op') OR jsonb_typeof(val -> 'op') = 'string')
     AND val - ARRAY['s', 'c', 'a', 'op', 'i', 'v', 'h']::text[] = '{}'::jsonb,
    false
  )
$$;

--! @brief Validate a SteVec containment query payload.
--! @internal
--! @param val jsonb Candidate query payload.
--! @return boolean True when `val` is `{"sv":[...]}` and every element carries
--!         a string `s`, no ciphertext, an optional string `op` (present only
--!         on ordered path entries), and no `hm`. A containment needle is a
--!         set of selectors — a value-selector's presence in the stored
--!         document IS the exact value match.
--! @note plpgsql, not LANGUAGE sql (issues #353/#354): the only caller is the
--!   eql_v3.query_json domain CHECK, where a SQL function can never be
--!   inlined (and the CHECK itself cannot absorb this body — it needs a
--!   subquery over the sv elements, which CHECK constraints forbid). plpgsql
--!   caches its plan across calls instead of paying the per-call SQL-function
--!   executor on every needle cast.
CREATE OR REPLACE FUNCTION public.eql_v3_is_valid_ste_vec_query_payload(val jsonb)
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
AS $$
BEGIN
  RETURN COALESCE(
    jsonb_typeof(val) = 'object'
     AND jsonb_typeof(val -> 'sv') = 'array'
     AND val - 'sv' = '{}'::jsonb
     AND NOT EXISTS (
       SELECT 1
       FROM jsonb_array_elements(
         CASE WHEN jsonb_typeof(val -> 'sv') = 'array' THEN val -> 'sv' ELSE '[]'::jsonb END
       ) AS elem
       WHERE NOT COALESCE((
         jsonb_typeof(elem) = 'object'
         AND jsonb_typeof(elem -> 's') = 'string'
         AND NOT (elem ? 'c')
         AND NOT (elem ? 'hm')
         AND (NOT (elem ? 'op') OR jsonb_typeof(elem -> 'op') = 'string')
         AND elem - ARRAY['s', 'op']::text[] = '{}'::jsonb
       ), false)
     ),
    false
  );
END;
$$;

--! @brief Validate a root SteVec document payload.
--! @internal
--! @param val jsonb Candidate document payload.
--! @return boolean True when `val` is an encrypted document envelope with
--!         `v = 3`, `i`, a string key header `h`, an `sv` array, and valid
--!         sv entry elements. `h` carries the document's key-retrieval
--!         material once (every entry encrypts under the document's single
--!         data key; entry `c` values are raw AEAD output whose nonces are
--!         derived from the entries' selectors) — it is opaque to SQL and
--!         only ever carried/grafted, never parsed. Unknown envelope keys are
--!         rejected; `k` and `a` remain optional compatibility fields.
CREATE OR REPLACE FUNCTION public.eql_v3_is_valid_ste_vec_document_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND val ? 'v'
     AND val ->> 'v' = '3'
     AND val ? 'i'
     AND jsonb_typeof(val -> 'h') = 'string'
     AND jsonb_typeof(val -> 'sv') = 'array'
     AND val - ARRAY['v', 'k', 'i', 'h', 'sv', 'a']::text[] = '{}'::jsonb
     AND NOT EXISTS (
       SELECT 1
       FROM jsonb_array_elements(
         CASE WHEN jsonb_typeof(val -> 'sv') = 'array' THEN val -> 'sv' ELSE '[]'::jsonb END
       ) AS elem
       WHERE NOT public.eql_v3_is_valid_ste_vec_entry_payload(elem)
     ),
    false
  )
$$;

--! @brief Storage/root domain for an encrypted JSONB column.
--!
--! CHECK: a JSON object carrying the EQL envelope (`v = 3` version, `i` index
--! metadata, and the key header `h`). Root `c` is intentionally NOT required —
--! an sv-array root payload is `{i, v, h, sv}` with no root ciphertext (the
--! root document ciphertext lives on the root sv entry). The CHECK also
--! requires an `sv` array, so the domain accepts only SteVec **document**
--! payloads and rejects encrypted *scalar* payloads (which carry `c`/`hm`/`ob`
--! but no `sv`) — this is what keeps `public.eql_v3_json_search` a typed
--! document domain rather than a generic encrypted envelope. The firewall in
--! blockers.sql attaches to this domain to stop native jsonb operators from
--! reaching a column value.
--!
--! @note Constructing from inline JSON uses the standard DOMAIN cast:
--!       `'{"i":{},"v":3,"h":"...","sv":[...]}'::public.eql_v3_json_search`.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_json_search' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_json_search AS jsonb
      CHECK (
        public.eql_v3_is_valid_ste_vec_document_payload(VALUE)
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_json_search IS 'EQL encrypted JSONB searchable document (containment)';
END
$$;

--! @brief Domain type for an individual sv element.
--!
--! A single element inside an `sv` array: a JSON object that carries a selector
--! (`s`) and a ciphertext (`c`), plus — for an ordered (number/string) path
--! entry only — a string `op` (CLLW OPE, for ordered queries). Value entries
--! (value-inclusive selectors) and non-orderable path entries are term-less
--! `{s, c}`: exact matching is selector presence, so there is no per-value
--! equality term (`hm` is retired and rejected). This is the type returned by
--! `->` and accepted by the per-entry extractors `eql_v3.ope_term` /
--! `eql_v3.ord_term`. The deprecated `eq_term(json_entry)` name aliases
--! `ope_term`. The optional array marker `a` and root `i`/`v`/`h`
--! metadata merged in by `->` are the only additional fields accepted.
--!
--! @see src/v3/json/operators.sql
--!
--! @internal
--! Implementation note (issue #354): the CHECK is an INLINE expression, not a
--! call to `public.eql_v3_is_valid_ste_vec_entry_payload` — domain
--! constraints cannot inline SQL functions, so the function-call form paid
--! the per-call SQL-function executor (~18 µs) on EVERY cast: the needle
--! cast in every field_eq query (+19% end-to-end vs v2, the entire measured
--! regression on that scenario; see cipherstash/benches#23). The expression
--! mirrors the validator body; the leading `VALUE IS NULL OR` preserves the
--! validator's STRICT NULL-passes semantics (a bare COALESCE(..., false)
--! would reject NULL, which `->` returns for a missing selector). Keep the
--! two in sync — `jsonb_entry_check_matches_validator` in tests/sqlx pins
--! the equivalence.
--! @endinternal
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'eql_v3_json_entry' AND typnamespace = 'public'::regnamespace
  ) THEN
    CREATE DOMAIN public.eql_v3_json_entry AS jsonb
      CHECK (
        VALUE IS NULL
        OR COALESCE(
          jsonb_typeof(VALUE) = 'object'
           AND jsonb_typeof(VALUE -> 's') = 'string'
           AND jsonb_typeof(VALUE -> 'c') = 'string'
           AND NOT (VALUE ? 'hm')
           AND (NOT (VALUE ? 'a') OR jsonb_typeof(VALUE -> 'a') = 'boolean')
           AND (NOT (VALUE ? 'op') OR jsonb_typeof(VALUE -> 'op') = 'string')
           AND VALUE - ARRAY['s', 'c', 'a', 'op', 'i', 'v', 'h']::text[] = '{}'::jsonb,
          false
        )
      );
  END IF;

  COMMENT ON DOMAIN public.eql_v3_json_entry IS 'EQL encrypted JSONB leaf entry (equality, ordering)';
END
$$;

--! @brief Domain type for an STE-vec containment needle.
--!
--! A query-shaped payload `{"sv":[...]}` whose elements carry selector + index
--! term but **never** a ciphertext (`c`). Each element carries `s`, an optional
--! `op` (ordered path entries only), and no `hm` — a containment needle is a
--! set of selectors, and a value-selector's presence in the stored document is
--! the exact value match. Typing the needle this way stops raw jsonb from
--! casting and matching every row via bare `jsonb @>`.
--!
--! @note Construct from inline JSON via the DOMAIN cast:
--!       `'{"sv":[{"s":"<sel>"}]}'::eql_v3.query_json`.
--! @see eql_v3.to_ste_vec_query
--!
--! @internal
--! Implementation note (issue #354): this CHECK CANNOT be inlined like
--! public.eql_v3_json_entry's — validating the sv elements requires a subquery
--! (`NOT EXISTS (SELECT ... FROM jsonb_array_elements(...))`), and CHECK
--! constraints forbid subqueries. The validator is plpgsql instead (cached
--! plan; substantially cheaper per call than a non-inlined LANGUAGE sql
--! function — the same finding as issue #353), since this cast sits on the
--! per-query hot path of every containment scenario
--! (`$1::jsonb::eql_v3.query_json`).
--! @endinternal
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'query_json' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.query_json AS jsonb
      CHECK (
        public.eql_v3_is_valid_ste_vec_query_payload(VALUE)
      );
  END IF;

  COMMENT ON DOMAIN eql_v3.query_json IS 'EQL JSONB query operand (containment)';
END
$$;

--! @brief Convert a public.eql_v3_json_search to a query_json needle.
--!
--! Normalises each sv element down to its selector `s`. Exact and structural
--! containment are both selector-set containment; an `op` carried by a legacy
--! or document-derived needle is accepted at the boundary for compatibility
--! but is not part of the containment predicate. Other fields are stripped.
--! This is the canonical needle shape for `@>` containment and the functional
--! GIN index expression:
--!   `GIN (eql_v3.to_ste_vec_query(col)::jsonb jsonb_path_ops)`.
--!
--! @param e public.eql_v3_json_search Source encrypted payload
--! @return eql_v3.query_json Query-shaped needle, sv elements normalised.
--! @see eql_v3.query_json
CREATE FUNCTION eql_v3.to_ste_vec_query(e public.eql_v3_json_search)
  RETURNS eql_v3.query_json
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT jsonb_build_object(
    'sv',
    coalesce(
      (SELECT jsonb_agg(
                jsonb_strip_nulls(
                  jsonb_build_object(
                    's', elem -> 's'
                  )
                )
              )
       FROM jsonb_array_elements(e::jsonb -> 'sv') AS elem),
      '[]'::jsonb
    )
  )::eql_v3.query_json
$$;

--! @brief Normalise an already query-shaped needle to selector-only form.
--!
--! Some producers derive a query from a complete encrypted document and may
--! therefore carry the path entry's `op`. Containment is selector-set
--! containment, so this overload strips `op` before comparison and keeps every
--! public containment entry point semantically identical.
CREATE FUNCTION eql_v3.to_ste_vec_query(e eql_v3.query_json)
  RETURNS eql_v3.query_json
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT jsonb_build_object(
    'sv',
    coalesce(
      (SELECT jsonb_agg(jsonb_build_object('s', elem -> 's'))
       FROM jsonb_array_elements(e::jsonb -> 'sv') AS elem),
      '[]'::jsonb
    )
  )::eql_v3.query_json
$$;

CREATE CAST (public.eql_v3_json_search AS eql_v3.query_json)
  WITH FUNCTION eql_v3.to_ste_vec_query(public.eql_v3_json_search)
  AS ASSIGNMENT;
