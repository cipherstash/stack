-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/crypto.sql
-- REQUIRE: src/v3/common.sql
-- REQUIRE: src/v3/sem/ore_block_256/types.sql

--! @file v3/sem/ore_block_256/functions.sql
--! @brief ORE block construction, extraction, and comparison ({{prefix}} SEM).
--!
--! jsonb-only subset of src/ore_block_u64_8_256/functions.sql. The
--! encrypted-column overloads are omitted; the helper jsonb_array_to_bytea_array
--! and pgcrypto encrypt() are reached via the forked src/v3/common.sql and
--! src/v3/crypto.sql so the whole closure stays under src/v3. (Doc comments
--! deliberately avoid naming eql_v2 symbols so the self-containment grep stays
--! clean.)

-- {{#v3}}
--! @brief Convert JSONB array to ORE block composite type
--! @internal
--! @param val jsonb Array of hex-encoded ORE block terms
--! @return {{prefix}}_internal.{{ore_block}} ORE block composite, or NULL if input is null
--! @note plpgsql, not `LANGUAGE sql` (issue #353). The sole caller
--!   (`{{ore_block}}`) is itself plpgsql, so this function is NEVER reached
--!   from an inlinable context — as `LANGUAGE sql` it paid the per-call
--!   SQL-function executor on every compared value in the opclass hot path
--!   (measured: +43% on ORE ordered scans vs the plpgsql form). The
--!   non-array guard preserves the v3 behaviour (returns NULL for a
--!   non-array scalar; the v2 plpgsql original raised); the caller only
--!   reaches this when `has_{{ore_block}}(val)` is true, which requires
--!   `val->'ob'` to be a JSON array, so that branch stays unreachable.
--!   An empty array (`ob: []`, what encrypting the empty string `""` produces)
--!   yields a non-NULL composite with an EMPTY `terms` array — NOT NULL terms.
--!   The `COALESCE` is load-bearing: `array_agg` over zero rows returns NULL, and
--!   NULL terms make the comparator return NULL (so an empty-text row silently
--!   drops out of ordered queries). An empty array instead engages the
--!   comparator's `cardinality = 0` guard, which sorts empty BEFORE every
--!   non-empty term. See issue #262 (pinned by T7).
CREATE FUNCTION {{prefix}}_internal.jsonb_array_to_{{ore_block}}(val jsonb)
RETURNS {{prefix}}_internal.{{ore_block}}
  IMMUTABLE
AS $$
DECLARE
  terms {{prefix}}_internal.{{ore_block}}_term[];
BEGIN
  IF val IS NULL OR jsonb_typeof(val) != 'array' THEN
    RETURN NULL;
  END IF;
  SELECT array_agg(ROW(b)::{{prefix}}_internal.{{ore_block}}_term)
    INTO terms
  FROM unnest({{prefix}}_internal.jsonb_array_to_bytea_array(val)) AS b;
  -- plpgsql pitfall: `SELECT <composite> INTO <composite-var>` assigns the
  -- select-list columns FIELD-WISE into the variable — return the row
  -- constructor directly instead. The COALESCE stays load-bearing for the
  -- empty-`ob` case (issue #262): array_agg over zero rows yields NULL, and
  -- the comparator needs an EMPTY terms array, not NULL terms.
  RETURN ROW(COALESCE(terms, ARRAY[]::{{prefix}}_internal.{{ore_block}}_term[]))::{{prefix}}_internal.{{ore_block}};
END;
$$ LANGUAGE plpgsql;

--! @internal Keep the inline-critical marker so the post-install
--! pin_search_path pass leaves this unpinned: a `SET search_path` clause on a
--! plpgsql function forces per-call configuration switching — measurable on a
--! helper invoked per compared value in the {{ore_block}} opclass hot path.
--! It takes a bare `jsonb` arg (not a jsonb-backed encrypted DOMAIN), so the
--! structural skip in tasks/pin_search_path_v3.sql does not recognise it;
--! this marker is the documented manual opt-in.
COMMENT ON FUNCTION {{prefix}}_internal.jsonb_array_to_{{ore_block}}(jsonb) IS
  'eql-inline-critical: per-encrypted-value ORE opclass-path helper; must stay unpinned (SET search_path adds per-call overhead)';
-- {{/v3}}


--! @brief Extract ORE block index term from JSONB payload
--! @param val jsonb containing encrypted EQL payload
--! @return {{prefix}}_internal.{{ore_block}} ORE block index term
--! @throws Exception if 'ob' field is missing
CREATE FUNCTION {{prefix}}_internal.{{ore_block}}(val jsonb)
  RETURNS {{prefix}}_internal.{{ore_block}}
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    -- Declared STRICT: PostgreSQL returns NULL for a NULL argument without
    -- entering the body, so no explicit `val IS NULL` guard is needed.
    IF {{prefix}}_internal.has_{{ore_block}}(val) THEN
-- {{#v3}}
      RETURN {{prefix}}_internal.jsonb_array_to_{{ore_block}}(val->'ob');
-- {{/v3}}
-- {{#v4}}
      -- One term, the hex of the whole ore-rs ciphertext. The domain CHECK
      -- has refused anything that is not a string with a block ORE prefix;
      -- decode() raises on a character that is not hex, and the comparator
      -- checks the rest of the structure.
      RETURN ROW(ROW(decode(val->>'ob', 'hex'))::{{prefix}}_internal.{{ore_block}}_term)::{{prefix}}_internal.{{ore_block}};
-- {{/v4}}
    END IF;
    RAISE 'Expected an ore index (ob) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if JSONB payload contains an ORE block index term
--! @param val jsonb containing encrypted EQL payload
-- {{#v3}}
--! @return boolean True only if the 'ob' field is present and is a JSON array
--! @note A well-formed ORE index term is always a JSON array of block terms, so
--!   this guard treats a present-but-non-array `ob` (a scalar or object) as
--!   absent. That makes the extractor `{{ore_block}}(val)` RAISE on a
--!   structurally invalid `ob` payload at the boundary instead of silently
--!   degrading it to a NULL index term in `jsonb_array_to_{{ore_block}}`. The
--!   previous `val ->> 'ob' IS NOT NULL` form stringified scalars/objects and so
--!   reported them as present. `{}` (absent `ob`) and `{"ob": null}` (JSON null)
--!   both remain `false`.
-- {{/v3}}
-- {{#v4}}
--! @return boolean True only if the 'ob' field is present and is a JSON string
--! @note A well-formed ORE index term is one hex string, the whole ore-rs
--!   ciphertext, so this guard treats a present `ob` of any other JSON type
--!   (an EQL v3 array, a number, an object) as absent, and the extractor
--!   `{{ore_block}}(val)` RAISEs on it. `{}` (absent `ob`) and
--!   `{"ob": null}` (JSON null) are `false`.
-- {{/v4}}
CREATE FUNCTION {{prefix}}_internal.has_{{ore_block}}(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
-- {{#v3}}
    RETURN COALESCE(jsonb_typeof(val -> 'ob') = 'array', false);
-- {{/v3}}
-- {{#v4}}
    RETURN COALESCE(jsonb_typeof(val -> 'ob') = 'string', false);
-- {{/v4}}
  END;
$$ LANGUAGE plpgsql;


-- {{#v3}}
--! @brief Compare two ORE block terms using cryptographic comparison
--! @internal
--! @param a {{prefix}}_internal.{{ore_block}}_term First ORE term
--! @param b {{prefix}}_internal.{{ore_block}}_term Second ORE term
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
--! @throws Exception if ciphertexts are different lengths
--! @note Marked `IMMUTABLE` (the three `compare_{{ore_block}}_term(s)`
--!   overloads all are). This deliberately diverges from the v2 originals,
--!   which carry no volatility marker and so default to `VOLATILE`. The
--!   comparison is deterministic — its only crypto call, pgcrypto `encrypt()`,
--!   is itself `IMMUTABLE STRICT PARALLEL SAFE` — so `IMMUTABLE` lets the
--!   planner fold/cache these in ordering and index contexts. NOT `STRICT`:
--!   the NULL-handling branches below are load-bearing for the array overload.
CREATE FUNCTION {{prefix}}_internal.compare_{{ore_block}}_term(a {{prefix}}_internal.{{ore_block}}_term, b {{prefix}}_internal.{{ore_block}}_term)
  RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    eq boolean := true;
    unequal_block smallint := 0;
    hash_key bytea;
    data_block bytea;
    encrypt_block bytea;
    target_block bytea;

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

    indicator smallint := 0;
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

    n := (octet_length(a.bytes) - 16) / 49;
    left_offset := 1 + n;     -- left blocks begin right after the N PRP bytes
    right_offset := 17 * n;   -- right CT begins right after the 17*N-byte left CT

    FOR block IN 0..n-1 LOOP
      -- Compare each PRP byte (the first N bytes) and its 16-byte left block.
      IF
        substr(a.bytes, 1 + block, 1) != substr(b.bytes, 1 + block, 1)
        OR substr(a.bytes, left_offset + left_block_size * block, left_block_size) != substr(b.bytes, left_offset + left_block_size * block, left_block_size)
      THEN
        IF eq THEN
          unequal_block := block;
        END IF;
        eq = false;
      END IF;
    END LOOP;

    IF eq THEN
      RETURN 0::integer;
    END IF;

    -- Hash key is the IV from the right CT of b.
    hash_key := substr(b.bytes, right_offset + 1, 16);

    -- First right block is at right_offset + nonce_size (ordinally indexed).
    target_block := substr(b.bytes, right_offset + 17 + (unequal_block * right_block_size), right_block_size);

    data_block := substr(a.bytes, left_offset + (left_block_size * unequal_block), left_block_size);

    encrypt_block := encrypt(data_block::bytea, hash_key::bytea, 'aes-ecb');

    indicator := (
      get_bit(
        encrypt_block,
        0
      ) + get_bit(target_block, get_byte(a.bytes, unequal_block))) % 2;

    IF indicator = 1 THEN
      RETURN 1::integer;
    ELSE
      RETURN -1::integer;
    END IF;
  END;
$$ LANGUAGE plpgsql;


--! @brief Compare arrays of ORE block terms recursively
--! @internal
--! @param a {{prefix}}_internal.{{ore_block}}_term[] First array
--! @param b {{prefix}}_internal.{{ore_block}}_term[] Second array
--! @return integer -1/0/1, or NULL if either array is NULL
CREATE FUNCTION {{prefix}}_internal.compare_{{ore_block}}_terms(a {{prefix}}_internal.{{ore_block}}_term[], b {{prefix}}_internal.{{ore_block}}_term[])
RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    cmp_result integer;
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

    cmp_result := {{prefix}}_internal.compare_{{ore_block}}_term(a[1], b[1]);

    IF cmp_result = 0 THEN
      RETURN {{prefix}}_internal.compare_{{ore_block}}_terms(a[2:array_length(a,1)], b[2:array_length(b,1)]);
    END IF;

    RETURN cmp_result;
  END
$$ LANGUAGE plpgsql;
-- {{/v3}}
-- {{#v4}}
--! @brief The 1-bit hash of a 6-bit block ORE comparison
--! @internal
--! @param f bytea The 16-byte left tag of the first differing block
--! @param nonce bytea The 16-byte nonce of the right-hand ciphertext
--! @return integer 0 or 1
--! @note The BHKR sigma-MMO hash ore-rs's 6-bit schemes use:
--!   `m = 2*f XOR nonce` (doubling in GF(2^128), big-endian, reduction
--!   constant 0x87), then the low bit of byte 0 of `AES(PI_KEY, m) XOR m`,
--!   where `PI_KEY` is the public, fixed AES key `ORE-rs.v2.H-pi.1`. The
--!   doubling is done on two `bigint` halves with no branch on the data. Its
--!   vectors are ore.rs's own (`tests/encryption/tests/v4_ore_block.rs`).
CREATE FUNCTION {{prefix}}_internal.{{ore_block}}_hash_bit(f bytea, nonce bytea)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    hi bigint := ('x' || encode(substr(f, 1, 8), 'hex'))::bit(64)::bigint;
    lo bigint := ('x' || encode(substr(f, 9, 8), 'hex'))::bit(64)::bigint;
    m bytea;
  BEGIN
    -- 2*f: shift the 128 bits left by one, carrying lo's top bit into hi,
    -- and fold hi's top bit back in as 0x87. Then XOR the nonce.
    m := int8send(((hi << 1) | (lo < 0)::int)
                  # ('x' || encode(substr(nonce, 1, 8), 'hex'))::bit(64)::bigint)
      || int8send(((lo << 1) # (135 * (hi < 0)::int))
                  # ('x' || encode(substr(nonce, 9, 8), 'hex'))::bit(64)::bigint);
    RETURN get_bit(encrypt(m, 'ORE-rs.v2.H-pi.1'::bytea, 'aes-ecb/pad:none'), 0)
         # get_bit(m, 0);
  END;
$$ LANGUAGE plpgsql;


--! @brief The scheme of a 6-bit block ORE term, checking its shape
--! @internal
--! @param t bytea A serialised ore-rs ciphertext
--! @return integer 2 for the fixed-width 6-bit scheme, 3 for the chained one
--! @throws Exception if `t` is not a well-formed ciphertext of either: a
--!   header of version 2, a block count of at least one (at most 14 for the
--!   fixed-width scheme, at most 1366 for the chained one), a length of
--!   exactly header + 25 bytes a block + a 16-byte nonce, a padding policy
--!   the chained scheme writes with a block count it can produce, and every
--!   permuted symbol below 64. The message names the length only, never the
--!   bytes.
--! @note The checks ore-rs's comparators make before they compare; every
--!   one is on the term's public structure. All of them are expressions,
--!   with no sub-select, because this runs on both operands of every
--!   comparison.
--! @note The chained bound is tighter than the wire format's 65,535 blocks.
--!   1366 blocks is a 1,024-byte string, the longest Stack Encrypt writes
--!   (ore-rs's default ceiling, which counts the marker byte before text
--!   and bytes). Comparing a term costs time in its block count, so a
--!   stored term past the bound would slow every comparison against it.
CREATE FUNCTION {{prefix}}_internal.{{ore_block}}_scheme(t bytea)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    len integer := octet_length(t);
    scheme integer;
    header integer;
    count integer;
    max_count integer;
    kind integer;
    policy integer;
    bucket integer;
    admitted boolean;
  BEGIN
    IF len < 7 OR get_byte(t, 0) <> 2 OR get_byte(t, 1) NOT IN (2, 3) THEN
      RAISE EXCEPTION 'Malformed ORE block term: % bytes', len;
    END IF;
    scheme := get_byte(t, 1);
    header := CASE scheme WHEN 2 THEN 4 ELSE 7 END;
    count := get_byte(t, 2) * 256 + get_byte(t, 3);
    max_count := CASE scheme WHEN 2 THEN 14 ELSE 1366 END;
    IF count < 1 OR count > max_count OR len <> header + 25 * count + 16 THEN
      RAISE EXCEPTION 'Malformed ORE block term: % bytes', len;
    END IF;
    IF scheme = 3 THEN
      -- The padding policy: none (0, 0), powers of two from a floor (1, n)
      -- or one fixed length (2, n), and a block count it can produce. A
      -- string of n bytes is ceil(8n / 6) blocks, which grows with n, so
      -- the one length that could give `count` blocks is floor(6 count / 8).
      kind := get_byte(t, 4);
      policy := get_byte(t, 5) * 256 + get_byte(t, 6);
      bucket := 6 * count / 8;
      admitted := CASE kind
        WHEN 0 THEN policy = 0
        WHEN 1 THEN policy <= 49151 AND (
          count = (8 * policy + 5) / 6
          OR (bucket > policy AND bucket & (bucket - 1) = 0
              AND count = (8 * bucket + 5) / 6))
        WHEN 2 THEN policy <= 49151 AND count = (8 * policy + 5) / 6
        ELSE false
      END;
      IF NOT admitted THEN
        RAISE EXCEPTION 'Malformed ORE block term: % bytes', len;
      END IF;
    END IF;
    -- A byte is below 64 exactly when its high hex digit is 0 to 3.
    IF encode(substr(t, header + 1, count), 'hex') !~ '^([0-3][0-9a-f])*$' THEN
      RAISE EXCEPTION 'Malformed ORE block term: % bytes', len;
    END IF;
    RETURN scheme;
  END;
$$ LANGUAGE plpgsql;


--! @brief Compare two 6-bit block ORE terms
--! @internal
--! @param a {{prefix}}_internal.{{ore_block}}_term First term: its left half is read
--! @param b {{prefix}}_internal.{{ore_block}}_term Second term: its right half is read
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
--! @throws Exception if either term is malformed
--!   (`{{prefix}}_internal.{{ore_block}}_scheme`), if the two are of different
--!   schemes, if two fixed-width terms have different block counts, or if
--!   two chained terms were padded under different policies. A mismatched
--!   pair raises rather than comparing to a meaningless answer.
--! @note Stack Encrypt writes ore-rs's 6-bit block ORE (ADR-0002): the
--!   fixed-width scheme (wire header `02 02`) for integers and floats, and
--!   the chained scheme (`02 03`, then a padding policy) for text. Both are
--!   ore-rs's wire version 2, which names the type here (`{{ore_block}}`);
--!   EQL v3's type of the same role compares cipherstash-client's 8-bit
--!   blocks, a different format under the same `ob` key.
--!   The layout after the header, for `count` blocks: `count` permuted
--!   symbols, `count` 16-byte left tags, a 16-byte nonce, then `count`
--!   8-byte right blocks. Chained terms compare lexicographically: if the
--!   shorter one's blocks all match, the shorter sorts first.
--! @note Constant operation count for operands of one shape (scheme and
--!   block counts, which a term's length reveals anyway). One statement per
--!   compared block evaluates both of its comparisons (integer `|`, which
--!   does not short-circuit) and latches the first differing block with
--!   arithmetic rather than an `IF`. The hash runs exactly once on every
--!   path, equal terms included (on block 0, its result discarded), and the
--!   result is selected arithmetically. PL/pgSQL is not a constant-time
--!   environment: C-level effects remain (`memcmp` stopping inside 16 bytes,
--!   the offset `substr` reads at). See `tests/timing/ore_block_v2/`.
CREATE FUNCTION {{prefix}}_internal.compare_{{ore_block}}_term(a {{prefix}}_internal.{{ore_block}}_term, b {{prefix}}_internal.{{ore_block}}_term)
  RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    ab bytea;
    bb bytea;
    scheme integer;
    header integer;
    ca integer;         -- a's block count
    cb integer;         -- b's block count
    nonce_b integer;    -- 0-based offset of b's nonce; its right blocks follow
    latch integer := 0; -- 1 + the first differing block, 0 while none differs
    first_diff integer;
    indicator integer;
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

    ab := a.bytes;
    bb := b.bytes;
    scheme := {{prefix}}_internal.{{ore_block}}_scheme(ab);
    IF {{prefix}}_internal.{{ore_block}}_scheme(bb) <> scheme THEN
      RAISE EXCEPTION 'ORE block terms of different schemes';
    END IF;
    header := CASE scheme WHEN 2 THEN 4 ELSE 7 END;
    ca := get_byte(ab, 2) * 256 + get_byte(ab, 3);
    cb := get_byte(bb, 2) * 256 + get_byte(bb, 3);
    IF scheme = 2 AND ca <> cb THEN
      RAISE EXCEPTION 'Ciphertexts are different lengths';
    END IF;
    IF scheme = 3 AND substr(ab, 5, 3) <> substr(bb, 5, 3) THEN
      RAISE EXCEPTION 'ORE block terms padded under different policies';
    END IF;
    nonce_b := header + 17 * cb;

    -- One statement per block, the same for every block.
    FOR block IN 0..least(ca, cb) - 1 LOOP
      latch := latch + (latch = 0)::int * (block + 1) * (
          (get_byte(ab, header + block) <> get_byte(bb, header + block))::int
        | (substr(ab, header + ca + 16 * block + 1, 16)
           <> substr(bb, header + cb + 16 * block + 1, 16))::int);
    END LOOP;

    -- Equal prefixes read block 0.
    first_diff := greatest(latch - 1, 0);

    -- One bit read and one hash on every path: bit `xt` of b's right block,
    -- XOR the hash of a's left tag under b's nonce. 1 means a > b.
    indicator := get_bit(
        substr(bb, nonce_b + 17 + 8 * first_diff, 8),
        get_byte(ab, header + first_diff))
      # {{prefix}}_internal.{{ore_block}}_hash_bit(
        substr(ab, header + ca + 16 * first_diff + 1, 16),
        substr(bb, nonce_b + 1, 16));

    -- No difference: the shorter sorts first (equal lengths are equal).
    -- Otherwise the indicator. No branch on the data.
    RETURN (latch = 0)::int * sign(ca - cb)::integer
         + (latch > 0)::int * (2 * indicator - 1);
  END;
$$ LANGUAGE plpgsql;
-- {{/v4}}


--! @brief Compare ORE block composite types
--! @internal
--! @param a {{prefix}}_internal.{{ore_block}} First ORE block
--! @param b {{prefix}}_internal.{{ore_block}} Second ORE block
--! @return integer -1/0/1
CREATE FUNCTION {{prefix}}_internal.compare_{{ore_block}}_terms(a {{prefix}}_internal.{{ore_block}}, b {{prefix}}_internal.{{ore_block}})
RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
-- {{#v3}}
    RETURN {{prefix}}_internal.compare_{{ore_block}}_terms(a.terms, b.terms);
-- {{/v3}}
-- {{#v4}}
    RETURN {{prefix}}_internal.compare_{{ore_block}}_term(a.term, b.term);
-- {{/v4}}
  END
$$ LANGUAGE plpgsql;
