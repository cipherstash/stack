-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/crypto.sql
-- REQUIRE: src/v3/common.sql
-- REQUIRE: src/v3/sem/ore_block_256/types.sql

--! @file v3/sem/ore_block_256/functions.sql
--! @brief ORE block construction, extraction, and comparison (eql_v3 SEM).
--!
--! jsonb-only subset of src/ore_block_u64_8_256/functions.sql. The
--! encrypted-column overloads are omitted; the helper jsonb_array_to_bytea_array
--! and pgcrypto encrypt() are reached via the forked src/v3/common.sql and
--! src/v3/crypto.sql so the whole closure stays under src/v3. (Doc comments
--! deliberately avoid naming eql_v2 symbols so the self-containment grep stays
--! clean.)

--! @brief Convert JSONB array to ORE block composite type
--! @internal
--! @param val jsonb Array of hex-encoded ORE block terms
--! @return eql_v3_internal.ore_block_256 ORE block composite, or NULL if input is null
--! @note plpgsql, not `LANGUAGE sql` (issue #353). The sole caller
--!   (`ore_block_256`) is itself plpgsql, so this function is NEVER reached
--!   from an inlinable context — as `LANGUAGE sql` it paid the per-call
--!   SQL-function executor on every compared value in the opclass hot path
--!   (measured: +43% on ORE ordered scans vs the plpgsql form). The
--!   non-array guard preserves the v3 behaviour (returns NULL for a
--!   non-array scalar; the v2 plpgsql original raised); the caller only
--!   reaches this when `has_ore_block_256(val)` is true, which requires
--!   `val->'ob'` to be a JSON array, so that branch stays unreachable.
--!   An empty array (`ob: []`, what encrypting the empty string `""` produces)
--!   yields a non-NULL composite with an EMPTY `terms` array — NOT NULL terms.
--!   The `COALESCE` is load-bearing: `array_agg` over zero rows returns NULL, and
--!   NULL terms make the comparator return NULL (so an empty-text row silently
--!   drops out of ordered queries). An empty array instead engages the
--!   comparator's `cardinality = 0` guard, which sorts empty BEFORE every
--!   non-empty term. See issue #262 (pinned by T7).
CREATE FUNCTION eql_v3_internal.jsonb_array_to_ore_block_256(val jsonb)
RETURNS eql_v3_internal.ore_block_256
  IMMUTABLE
AS $$
DECLARE
  terms eql_v3_internal.ore_block_256_term[];
BEGIN
  IF val IS NULL OR jsonb_typeof(val) != 'array' THEN
    RETURN NULL;
  END IF;
  SELECT array_agg(ROW(b)::eql_v3_internal.ore_block_256_term)
    INTO terms
  FROM unnest(eql_v3_internal.jsonb_array_to_bytea_array(val)) AS b;
  -- plpgsql pitfall: `SELECT <composite> INTO <composite-var>` assigns the
  -- select-list columns FIELD-WISE into the variable — return the row
  -- constructor directly instead. The COALESCE stays load-bearing for the
  -- empty-`ob` case (issue #262): array_agg over zero rows yields NULL, and
  -- the comparator needs an EMPTY terms array, not NULL terms.
  RETURN ROW(COALESCE(terms, ARRAY[]::eql_v3_internal.ore_block_256_term[]))::eql_v3_internal.ore_block_256;
END;
$$ LANGUAGE plpgsql;

--! @internal Keep the inline-critical marker so the post-install
--! pin_search_path pass leaves this unpinned: a `SET search_path` clause on a
--! plpgsql function forces per-call configuration switching — measurable on a
--! helper invoked per compared value in the ore_block_256 opclass hot path.
--! It takes a bare `jsonb` arg (not a jsonb-backed encrypted DOMAIN), so the
--! structural skip in tasks/pin_search_path_v3.sql does not recognise it;
--! this marker is the documented manual opt-in.
COMMENT ON FUNCTION eql_v3_internal.jsonb_array_to_ore_block_256(jsonb) IS
  'eql-inline-critical: per-encrypted-value ORE opclass-path helper; must stay unpinned (SET search_path adds per-call overhead)';


--! @brief Extract ORE block index term from JSONB payload
--! @param val jsonb containing encrypted EQL payload
--! @return eql_v3_internal.ore_block_256 ORE block index term
--! @throws Exception if 'ob' field is missing
CREATE FUNCTION eql_v3_internal.ore_block_256(val jsonb)
  RETURNS eql_v3_internal.ore_block_256
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    -- Declared STRICT: PostgreSQL returns NULL for a NULL argument without
    -- entering the body, so no explicit `val IS NULL` guard is needed.
    IF eql_v3_internal.has_ore_block_256(val) THEN
      RETURN eql_v3_internal.jsonb_array_to_ore_block_256(val->'ob');
    END IF;
    RAISE 'Expected an ore index (ob) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if JSONB payload contains an ORE block index term
--! @param val jsonb containing encrypted EQL payload
--! @return boolean True only if the 'ob' field is present and is a JSON array
--! @note A well-formed ORE index term is always a JSON array of block terms, so
--!   this guard treats a present-but-non-array `ob` (a scalar or object) as
--!   absent. That makes the extractor `ore_block_256(val)` RAISE on a
--!   structurally invalid `ob` payload at the boundary instead of silently
--!   degrading it to a NULL index term in `jsonb_array_to_ore_block_256`. The
--!   previous `val ->> 'ob' IS NOT NULL` form stringified scalars/objects and so
--!   reported them as present. `{}` (absent `ob`) and `{"ob": null}` (JSON null)
--!   both remain `false`.
CREATE FUNCTION eql_v3_internal.has_ore_block_256(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN COALESCE(jsonb_typeof(val -> 'ob') = 'array', false);
  END;
$$ LANGUAGE plpgsql;


--! @brief Compare two ORE block terms using cryptographic comparison
--! @internal
--! @param a eql_v3_internal.ore_block_256_term First ORE term
--! @param b eql_v3_internal.ore_block_256_term Second ORE term
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
--! @throws Exception if ciphertexts are different lengths
--! @note Marked `IMMUTABLE` (the three `compare_ore_block_256_term(s)`
--!   overloads all are). This deliberately diverges from the v2 originals,
--!   which carry no volatility marker and so default to `VOLATILE`. The
--!   comparison is deterministic — its only crypto call, pgcrypto `encrypt()`,
--!   is itself `IMMUTABLE STRICT PARALLEL SAFE` — so `IMMUTABLE` lets the
--!   planner fold/cache these in ordering and index contexts. NOT `STRICT`:
--!   the NULL-handling branches below are load-bearing for the array overload.
--! @note Constant operation count. Past the NULL and length checks (public
--!   properties), every comparison executes the same statements whatever the
--!   operands: one statement per block, which evaluates both of the block's
--!   comparisons (integer `|`, which unlike `OR` does not short-circuit) and
--!   latches the first differing block with arithmetic rather than an `IF`;
--!   then one `encrypt()`, two `get_bit()` and one `get_byte()`, on every
--!   path including for equal terms. An earlier form ran extra statements on
--!   every block after the first difference and skipped a comparison on each
--!   of them, so its time depended on where the operands first differ, which
--!   is the information the constant-time comparator in ore.rs keeps from
--!   anyone timing a query. Measured on PostgreSQL 17 (aarch64) through
--!   `compare_ore_block_256_terms`, 200 k samples of 16 comparisons, operands
--!   differing in the first block against operands differing only in the
--!   last: the old form gave t = +4.9 and +13.9 (its extra statements and its
--!   skipped comparisons mostly cancel on that machine, which no platform
--!   guarantees; with the short-circuit removed it gave t = +388, about
--!   0.7 µs per comparison). See `tests/timing/ore_block_256/` for this
--!   form's figures. PL/pgSQL is not a constant-time environment, so C-level
--!   effects remain (`memcmp` within 16 bytes, the offset `substr` reads at),
--!   orders of magnitude below one statement.
CREATE FUNCTION eql_v3_internal.compare_ore_block_256_term(a eql_v3_internal.ore_block_256_term, b eql_v3_internal.ore_block_256_term)
  RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    ab bytea;
    bb bytea;

    left_block_size CONSTANT smallint := 16;
    right_block_size CONSTANT smallint := 32;

    -- Block count N is DERIVED from the ciphertext length, not hardcoded to 8.
    -- Wire format per term:
    --   [ N PRP bytes ][ N*16B left blocks ][ 16B hash key ][ N*32B right blocks ]
    --   octet_length = 17*N + 16 + 32*N = 49*N + 16  =>  N = (octet_length - 16) / 49
    -- This serves integer (N=8, 408B), timestamp (N=12, 604B), and numeric
    -- (N=14, 702B) with one comparator.
    n            integer;
    left_offset  integer;  -- ordinal offset of the first left block (1 + N PRP bytes)
    right_offset integer;  -- ordinal start of the right CT (= total left CT length = 17*N)

    latch      integer := 0; -- 1 + the first differing block, 0 while none differs
    first_diff integer;      -- first differing block (0 if the terms are equal)
    indicator  integer;
  BEGIN
    IF a IS NULL AND b IS NULL THEN
      RETURN 0;
    END IF;

    IF a IS NULL THEN
      RETURN -1;
    END IF;

    IF b IS NULL THEN
      RETURN 1;
    END IF;

    IF bit_length(a.bytes) != bit_length(b.bytes) THEN
      RAISE EXCEPTION 'Ciphertexts are different lengths';
    END IF;

    -- Well-formedness: length must be exactly 49*N + 16 for some N >= 1. The
    -- modulo alone is insufficient -- a 16-byte term passes (16 - 16) % 49 = 0
    -- and derives N = 0, which would fall through to the all-blocks-equal path
    -- and return 0 instead of raising. The `<= 16` clause is load-bearing.
    IF octet_length(a.bytes) <= 16 OR (octet_length(a.bytes) - 16) % 49 != 0 THEN
      RAISE EXCEPTION 'Malformed ORE term: % bytes', octet_length(a.bytes);
    END IF;

    ab := a.bytes;
    bb := b.bytes;
    n := (octet_length(ab) - 16) / 49;
    left_offset := 1 + n;     -- left blocks begin right after the N PRP bytes
    right_offset := 17 * n;   -- right CT begins right after the 17*N-byte left CT

    -- One statement per block, the same for every block: both comparisons
    -- always evaluated, and the first differing block latched as block + 1
    -- while the latch is still 0.
    FOR block IN 0..n-1 LOOP
      latch := latch + (latch = 0)::int * (block + 1) * (
          (substr(ab, 1 + block, 1) <> substr(bb, 1 + block, 1))::int
        | (substr(ab, left_offset + left_block_size * block, left_block_size)
           <> substr(bb, left_offset + left_block_size * block, left_block_size))::int);
    END LOOP;

    -- Equal terms read block 0.
    first_diff := greatest(latch - 1, 0);

    -- One hash and one bit read on every path. For equal terms this reads
    -- block 0 and the result is discarded below. The hash key is the IV at
    -- the start of b's right CT; the right blocks follow it.
    indicator := (
      get_bit(
        encrypt(
          substr(ab, left_offset + left_block_size * first_diff, left_block_size),
          substr(bb, right_offset + 1, 16),
          'aes-ecb'),
        0)
      + get_bit(
          substr(bb, right_offset + 17 + right_block_size * first_diff, right_block_size),
          get_byte(ab, first_diff))) % 2;

    -- 0 when equal, otherwise +1 / -1 from the indicator; no branch on the data.
    RETURN sign(latch) * (2 * indicator - 1);
  END;
$$ LANGUAGE plpgsql;


--! @brief Compare arrays of ORE block terms lexicographically
--! @internal
--! @param a eql_v3_internal.ore_block_256_term[] First array
--! @param b eql_v3_internal.ore_block_256_term[] Second array
--! @return integer -1/0/1, or NULL if either array is NULL
--! @throws Exception if paired terms are different lengths, or any paired
--!   term is malformed
--! @note Single-term values (every type but text) go straight to
--!   `compare_ore_block_256_term`. Multi-term values (text, up to six terms)
--!   are compared with a constant operation count across the terms. A
--!   term-by-term comparison that stops at the first unequal term takes time
--!   proportional to how many leading terms are equal, which reveals the
--!   length of the shared prefix: measured on PostgreSQL 17, six-term values
--!   took about 11 µs when the first terms differ and 47 µs when only the
--!   sixth does (t below -1500). Instead, every paired term is compared whole
--!   in one statement (its PRP bytes and left blocks, which are deterministic)
--!   and the first unequal one is latched with arithmetic. Then exactly one
--!   call to `compare_ore_block_256_term` runs on every path: on the latched
--!   pair, or, when every paired term is equal or the latched pair has a NULL
--!   element, on a pair whose result is discarded. The result is selected
--!   with arithmetic, so neither a shared prefix of different-length arrays
--!   nor a NULL element after equal terms skips the hash. Term counts and the
--!   positions of NULL elements are public structure and may branch. If every
--!   paired term is equal, the shorter array sorts first. C-level effects
--!   remain: the whole-term `memcmp` stops at the first differing byte, a
--!   few nanoseconds over at most a few hundred bytes. See
--!   `tests/timing/ore_block_256/`.
CREATE FUNCTION eql_v3_internal.compare_ore_block_256_terms(a eql_v3_internal.ore_block_256_term[], b eql_v3_internal.ore_block_256_term[])
RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF a IS NULL OR b IS NULL THEN
      RETURN NULL;
    END IF;

    IF cardinality(a) = 0 AND cardinality(b) = 0 THEN
      RETURN 0;
    END IF;

    IF (cardinality(a) = 0) AND cardinality(b) > 0 THEN
      RETURN -1;
    END IF;

    IF cardinality(a) > 0 AND (cardinality(b) = 0) THEN
      RETURN 1;
    END IF;

    IF cardinality(a) = 1 AND cardinality(b) = 1 THEN
      RETURN eql_v3_internal.compare_ore_block_256_term(a[1], b[1]);
    END IF;

    -- Multi-term path. Its variables are declared in this inner block, not at
    -- the top: PL/pgSQL evaluates every initialised declaration on each call,
    -- and the single-term path above is the operator-class hot path.
    DECLARE
      ab bytea;
      bb bytea;
      differs integer;         -- 1 if the current pair differs
      null_order integer;      -- the current pair's order if it has a NULL element, else 0

      latch integer := 0;      -- the first unequal pair's index, 0 while every pair is equal
      first_null integer := 0; -- the latched pair's NULL ordering, 0 if it has none
      spare integer := 0;      -- the first pair with no NULL element (structure), 0 if none
      h integer;               -- the pair compare_ore_block_256_term runs on
      r integer;
    BEGIN
      FOR t IN 1..least(cardinality(a), cardinality(b)) LOOP
        ab := a[t].bytes;
        bb := b[t].bytes;

        -- The length check comes first, as in compare_ore_block_256_term, so
        -- both paths report the same error for the same pair.
        IF octet_length(ab) != octet_length(bb) THEN
          RAISE EXCEPTION 'Ciphertexts are different lengths';
        END IF;
        IF ab IS NOT NULL AND (octet_length(ab) <= 16 OR (octet_length(ab) - 16) % 49 != 0) THEN
          RAISE EXCEPTION 'Malformed ORE term: % bytes', octet_length(ab);
        END IF;
        IF bb IS NOT NULL AND (octet_length(bb) <= 16 OR (octet_length(bb) - 16) % 49 != 0) THEN
          RAISE EXCEPTION 'Malformed ORE term: % bytes', octet_length(bb);
        END IF;

        -- NULL elements are structure, not data: they may branch.
        IF ab IS NULL OR bb IS NULL THEN
          differs := ((ab IS NULL) <> (bb IS NULL))::int;
          null_order := (bb IS NULL)::int - (ab IS NULL)::int;
        ELSE
          -- The PRP bytes and left blocks: the first 17*N bytes.
          differs := (substr(ab, 1, 17 * ((octet_length(ab) - 16) / 49))
                      <> substr(bb, 1, 17 * ((octet_length(ab) - 16) / 49)))::int;
          null_order := 0;
          IF spare = 0 THEN
            spare := t;
          END IF;
        END IF;

        -- Latch the first unequal pair without a branch.
        first_null := first_null + (latch = 0)::int * differs * null_order;
        latch := latch + (latch = 0)::int * differs * t;
      END LOOP;

      -- One term comparison on every path. It runs on the latched pair, or on
      -- pair 1 when every pair is equal; if that pair has a NULL element, on
      -- the first pair with none. Only when no pair is free of NULLs (which
      -- is structure) does it take its NULL branch.
      h := greatest(latch, 1);
      h := h + ((a[h] IS NULL)::int | (b[h] IS NULL)::int) * (spare - h);
      r := eql_v3_internal.compare_ore_block_256_term(a[h], b[h]);

      -- Every pair equal: the shorter array sorts first. Otherwise the
      -- latched pair's NULL ordering, or the term comparison.
      RETURN (latch = 0)::int * sign(cardinality(a) - cardinality(b))::integer
           + (latch > 0)::int * (first_null + (first_null = 0)::int * r);
    END;
  END
$$ LANGUAGE plpgsql;


--! @brief Compare ORE block composite types
--! @internal
--! @param a eql_v3_internal.ore_block_256 First ORE block
--! @param b eql_v3_internal.ore_block_256 Second ORE block
--! @return integer -1/0/1
CREATE FUNCTION eql_v3_internal.compare_ore_block_256_terms(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v3_internal.compare_ore_block_256_terms(a.terms, b.terms);
  END
$$ LANGUAGE plpgsql;
