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
--!   operands: each block evaluates both of its comparisons (integer `|`, which
--!   unlike `OR` does not short-circuit), the first differing block is latched
--!   with arithmetic rather than an `IF`, and exactly one `encrypt()` and one
--!   `get_bit()` run on every path, including for equal terms. An earlier form
--!   ran extra statements on every block after the first difference and skipped
--!   a comparison on each of them, so its time depended on where the operands
--!   first differ, which is the information the constant-time comparator in
--!   ore.rs keeps from anyone timing a query. Measured on PostgreSQL 17
--!   (aarch64) through `compare_ore_block_256_terms`, 200 k samples of 16
--!   comparisons, operands differing in the first block against operands
--!   differing only in the last: the old form gave t = +4.9 and +13.9 (its
--!   extra statements and its skipped comparisons mostly cancel on that
--!   machine, which no platform guarantees; with the short-circuit removed it
--!   gave t = +388, about 0.7 µs per comparison). This form: t = +1.8 and
--!   +1.1, at about 3-8% more time per comparison. The blocks' results are
--!   collected one statement per block into a bitmask whose lowest set bit is
--!   the first difference. PL/pgSQL is not a constant-time environment, so
--!   C-level effects remain (`memcmp` within 16 bytes, the offset `substr`
--!   reads at), orders of magnitude below one statement. See
--!   `tests/timing/ore_block_256/`.
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

    diff_mask  integer := 0; -- bit k set iff block k differs (N <= 14 fits)
    still_eq   integer;      -- 1 if no block differs
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
    -- always evaluated, the result recorded as a bit of diff_mask.
    FOR block IN 0..n-1 LOOP
      diff_mask := diff_mask | ((
          (substr(ab, 1 + block, 1) <> substr(bb, 1 + block, 1))::int
        | (substr(ab, left_offset + left_block_size * block, left_block_size)
           <> substr(bb, left_offset + left_block_size * block, left_block_size))::int
        ) << block);
    END LOOP;

    -- The first differing block is the lowest set bit: isolate it
    -- (mask & -mask, a power of two) and take its exact base-2 logarithm,
    -- with no loop or branch. An empty mask reads block 0.
    still_eq := (diff_mask = 0)::int;
    first_diff := round(ln(greatest(diff_mask & -diff_mask, 1)) / ln(2))::int;

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
    RETURN (1 - still_eq) * (2 * indicator - 1);
  END;
$$ LANGUAGE plpgsql;


--! @brief Compare arrays of ORE block terms lexicographically
--! @internal
--! @param a eql_v3_internal.ore_block_256_term[] First array
--! @param b eql_v3_internal.ore_block_256_term[] Second array
--! @return integer -1/0/1, or NULL if either array is NULL
--! @throws Exception if paired terms are different lengths or malformed
--! @note Single-term values (every type but text) go straight to
--!   `compare_ore_block_256_term`. Multi-term values (text, up to six terms)
--!   are compared with a constant operation count across the terms: every
--!   paired term is scanned, the first unequal term and its first differing
--!   block are latched with arithmetic, and one `encrypt()` resolves the
--!   order. A term-by-term comparison that stops at the first unequal term
--!   takes time proportional to how many leading terms are equal, which
--!   reveals the length of the shared prefix: measured on PostgreSQL 17,
--!   six-term values took about 11 µs when the first terms differ and 47 µs
--!   when only the sixth does (t below -1500). This form takes about 31 µs
--!   either way (t = +4.5 and +2.7). Term counts and NULL elements
--!   are public structure and may branch. If every paired term is equal, the
--!   shorter array sorts first. Every paired term is length-checked, including
--!   those after the first unequal one.
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
      left_block_size CONSTANT smallint := 16;
      right_block_size CONSTANT smallint := 32;

      m integer;              -- paired terms: least(cardinality(a), cardinality(b))
      ab bytea;
      bb bytea;
      n integer;
      left_offset integer;
      right_offset integer;

      differs integer;        -- 1 if the current term differs
      diff_mask integer;      -- bit k set iff block k of the current term differs
      term_diff integer;      -- first differing block within the current term
      null_order integer;     -- for a pair with a NULL element: -1 / 1

      still_eq integer := 1;   -- 1 until the first unequal term
      first_term integer := 1;
      first_block integer := 0;
      first_null integer := 0; -- the latched pair's NULL ordering, 0 if none
      indicator integer;
    BEGIN
      m := least(cardinality(a), cardinality(b));

      FOR t IN 1..m LOOP
        -- NULL elements are structure, not data: they may branch.
        IF a[t] IS NULL OR b[t] IS NULL THEN
          differs := ((a[t] IS NULL) <> (b[t] IS NULL))::int;
          null_order := CASE WHEN a[t] IS NULL THEN -1 ELSE 1 END;
          term_diff := 0;
        ELSE
          IF bit_length(a[t].bytes) != bit_length(b[t].bytes) THEN
            RAISE EXCEPTION 'Ciphertexts are different lengths';
          END IF;
          IF octet_length(a[t].bytes) <= 16 OR (octet_length(a[t].bytes) - 16) % 49 != 0 THEN
            RAISE EXCEPTION 'Malformed ORE term: % bytes', octet_length(a[t].bytes);
          END IF;

          ab := a[t].bytes;
          bb := b[t].bytes;
          n := (octet_length(ab) - 16) / 49;
          left_offset := 1 + n;

          diff_mask := 0;
          FOR block IN 0..n-1 LOOP
            diff_mask := diff_mask | ((
                (substr(ab, 1 + block, 1) <> substr(bb, 1 + block, 1))::int
              | (substr(ab, left_offset + left_block_size * block, left_block_size)
                 <> substr(bb, left_offset + left_block_size * block, left_block_size))::int
              ) << block);
          END LOOP;
          differs := (diff_mask <> 0)::int;
          term_diff := round(ln(greatest(diff_mask & -diff_mask, 1)) / ln(2))::int;
          null_order := 0;
        END IF;

        -- Latch the first unequal pair without a branch.
        first_term := first_term + still_eq * differs * (t - 1);
        first_block := first_block + still_eq * differs * term_diff;
        first_null := first_null + still_eq * differs * null_order;
        still_eq := still_eq * (1 - differs);
      END LOOP;

      -- Every paired term equal: the shorter array sorts first.
      IF still_eq = 1 THEN
        RETURN sign(cardinality(a) - cardinality(b))::integer;
      END IF;

      -- The first unequal pair had a NULL element: its order is structural.
      IF first_null <> 0 THEN
        RETURN first_null;
      END IF;

      -- One hash and one bit read, on the latched term and block.
      ab := a[first_term].bytes;
      bb := b[first_term].bytes;
      n := (octet_length(ab) - 16) / 49;
      left_offset := 1 + n;
      right_offset := 17 * n;
      indicator := (
        get_bit(
          encrypt(
            substr(ab, left_offset + left_block_size * first_block, left_block_size),
            substr(bb, right_offset + 1, 16),
            'aes-ecb'),
          0)
        + get_bit(
            substr(bb, right_offset + 17 + right_block_size * first_block, right_block_size),
            get_byte(ab, first_block))) % 2;

      RETURN 2 * indicator - 1;
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
