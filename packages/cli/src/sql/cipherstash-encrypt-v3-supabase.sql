--! @file v3/schema.sql
--! @brief EQL v3 schema creation
--!
--! Creates the eql_v3 schema, which houses the self-contained encrypted-domain
--! type families (eql_v3.int4, eql_v3.int8, and future scalar domains): their
--! jsonb-backed domains, the searchable-encrypted-metadata (SEM) index-term
--! types they use (eql_v3.hmac_256, eql_v3.ore_block_256), the index-term
--! extractors, comparison wrappers, blockers, and aggregates. The v3 surface is
--! self-contained — it owns every type it needs and has no runtime dependency
--! on another EQL schema.
--!
--! Drops existing schema if present to support clean reinstallation.
--!
--! @warning DROP SCHEMA CASCADE will remove all objects in the schema
--! @note eql_v3 is a new, additional schema for the encrypted-domain families.

--! @brief Drop existing EQL v3 schema
--! @warning CASCADE will drop all dependent objects
DROP SCHEMA IF EXISTS eql_v3 CASCADE;

--! @brief Create EQL v3 schema
--! @note Houses the encrypted-domain type families
CREATE SCHEMA eql_v3;

--! @file v3/sem/ore_block_256/types.sql
--! @brief ORE block index-term types (eql_v3 SEM).
--!
--! Self-contained eql_v3 copies of the Order-Revealing Encryption block types
--! (design D1/D3). The eql_v2 originals are unchanged.

--! @brief ORE block term type for Order-Revealing Encryption
--!
--! Composite type representing a single ORE block term. Stores encrypted data
--! as bytea that enables range comparisons without decryption.
CREATE TYPE eql_v3.ore_block_256_term AS (
  bytes bytea
);


--! @brief ORE block index term type for range queries
--!
--! Composite type containing an array of ORE block terms. The array is stored
--! in the 'ob' field of encrypted data payloads.
--!
--! @note Transient type used only during query execution.
CREATE TYPE eql_v3.ore_block_256 AS (
  terms eql_v3.ore_block_256_term[]
);

--! @file v3/crypto.sql
--! @brief PostgreSQL pgcrypto extension enablement (eql_v3 fork)
--!
--! Forked from src/crypto.sql (design D8) so the entire eql_v3 dependency
--! closure lives under src/v3/. Enables the pgcrypto extension which provides
--! cryptographic functions used by the eql_v3 ORE comparison path.
--!
--! Installs pgcrypto into the `extensions` schema (Supabase convention) to
--! avoid the `extension_in_public` lint. Every EQL function that uses pgcrypto
--! has `pg_catalog, extensions, public` on its `search_path`, so a pre-existing
--! install in `public` keeps working — and a pre-existing install anywhere else
--! will be rejected at install time. The body is idempotent
--! (`CREATE SCHEMA IF NOT EXISTS`, `pg_extension` guard), so running it
--! alongside the eql_v2 copy in a combined install is safe.
--!
--! @note pgcrypto provides functions like digest(), hmac(), gen_random_bytes()

--! @brief Create extensions schema (Supabase convention)
CREATE SCHEMA IF NOT EXISTS extensions;

--! @brief Enable pgcrypto extension and validate its schema
DO $$
DECLARE
  pgcrypto_schema name;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
    CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
  END IF;

  SELECT n.nspname INTO pgcrypto_schema
  FROM pg_extension e
  JOIN pg_namespace n ON n.oid = e.extnamespace
  WHERE e.extname = 'pgcrypto';

  IF pgcrypto_schema = 'extensions' THEN
    -- expected location, nothing to say
    NULL;
  ELSIF pgcrypto_schema = 'public' THEN
    RAISE NOTICE
      'pgcrypto is installed in the `public` schema. EQL works against this layout, '
      'but Supabase splinter will flag it as `extension_in_public`. Move it with: '
      'ALTER EXTENSION pgcrypto SET SCHEMA extensions';
  ELSE
    RAISE EXCEPTION
      'pgcrypto is installed in schema `%`, which is not on the EQL function search_path '
      '(pg_catalog, extensions, public). EQL cryptographic operations would fail at '
      'runtime. Relocate the extension before installing EQL: '
      'ALTER EXTENSION pgcrypto SET SCHEMA extensions',
      pgcrypto_schema;
  END IF;
END $$;

--! @file v3/common.sql
--! @brief Common utility functions for the self-contained eql_v3 surface.
--!
--! Forked from src/common.sql (design D7) so the eql_v3 ORE constructor owns the
--! one transitive helper it needs without reaching into another schema. The
--! eql_v2 original is unchanged.

--! @brief Convert JSONB hex array to bytea array
--! @internal
--!
--! Converts a JSONB array of hex-encoded strings into a PostgreSQL bytea array.
--! Used for deserializing binary data (like ORE terms) from JSONB storage.
--!
--! @param val jsonb JSONB array of hex-encoded strings
--! @return bytea[] Array of decoded binary values
--!
--! @note Returns NULL if input is JSON null
--! @note Each array element is hex-decoded to bytea
--! @note Inlinable `LANGUAGE sql` IMMUTABLE form (no `SET search_path`) so the
--!   planner can fold this per-encrypted-value helper into the calling query.
--!   This deliberately diverges from the v2 plpgsql equivalent (intentionally
--!   left unchanged): the `CASE WHEN jsonb_typeof(val) = 'array'` guard only
--!   evaluates the set-returning `jsonb_array_elements_text` for an array, so a
--!   non-array JSON scalar returns NULL here instead of raising "cannot extract
--!   elements from a scalar". Both callers only ever pass an array or JSON null
--!   (`val->'ob'`), so the divergence is unreachable in practice; JSON null and
--!   empty array still return NULL exactly as before.
CREATE FUNCTION eql_v3.jsonb_array_to_bytea_array(val jsonb)
RETURNS bytea[]
  IMMUTABLE
AS $$
  SELECT CASE WHEN jsonb_typeof(val) = 'array'
    THEN (
      SELECT array_agg(decode(value::text, 'hex')::bytea)
      FROM jsonb_array_elements_text(val) AS value
    )
    ELSE NULL
  END;
$$ LANGUAGE sql;

--! @internal Mark this hand-written helper inline-critical so the post-install
--! pin_search_path pass leaves it unpinned (no `SET search_path`), preserving
--! SQL-function inlining. It takes a bare `jsonb` arg (not a jsonb-backed
--! encrypted DOMAIN), so the structural skip in tasks/pin_search_path.sql does
--! not recognise it; this marker is the documented manual opt-in.
COMMENT ON FUNCTION eql_v3.jsonb_array_to_bytea_array(jsonb) IS
  'eql-inline-critical: per-encrypted-value ORE helper; must stay inlinable (unpinned search_path)';

--! @file v3/sem/hmac_256/types.sql
--! @brief HMAC-SHA256 index term type (eql_v3 SEM)
--!
--! Domain type representing HMAC-SHA256 hash values. Used for exact-match
--! encrypted searches. The hash is stored in the 'hm' field of encrypted data
--! payloads. Self-contained eql_v3 copy (design D1/D3); the eql_v2 original is
--! unchanged.
--!
--! @note Transient type used only during query execution.
CREATE DOMAIN eql_v3.hmac_256 AS text;

--! @file v3/sem/bloom_filter/types.sql
--! @brief Self-contained eql_v3 Bloom-filter SEM index-term type.

--! @brief Bloom-filter index term: a bit array stored as smallint[].
--!
--! Backs the `match` capability (`@>` / `<@`) on `eql_v3.text_match`. The
--! filter is read from the `bf` field of an encrypted jsonb payload. Native
--! `smallint[]` array-containment (`@>`/`<@`) is inherited through the domain,
--! so this type needs no custom operators.
--!
--! @note Self-contained: references no eql_v2 symbol.
CREATE DOMAIN eql_v3.bloom_filter AS smallint[];

--! @file v3/scalars/functions.sql
--! @brief Shared blocker helper for the eql_v3 encrypted-domain families.
--!
--! Per-domain wrapper functions live in src/v3/scalars/<T>/.
--! Blockers in those files delegate to encrypted_domain_unsupported_bool
--! so every domain raises a uniform domain-specific error rather than
--! letting an unsupported operator fall through to native jsonb
--! behaviour.

--! @brief Shared blocker helper. Raises 'operator X is not supported
--!        for TYPE' so unsupported domain operators surface a clear
--!        error rather than fall through to native jsonb behaviour.
--! @param type_name Domain type name (eql_v3.<T>*)
--! @param operator_name Operator symbol (=, <, @>, ->, etc.)
--! @return boolean (never returns; always raises)
CREATE FUNCTION eql_v3.encrypted_domain_unsupported_bool(type_name text, operator_name text)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;

--! @brief Shared blocker helper returning jsonb. Identical to
--!        encrypted_domain_unsupported_bool but typed for blockers shadowing
--!        native operators whose result is jsonb (#>, -, #-, ||), so composed
--!        expressions resolve and the body raises rather than failing earlier
--!        with a misleading 'operator does not exist' on a boolean result.
--! @param type_name Domain type name (eql_v3.<T>*)
--! @param operator_name Operator symbol (#>, -, #-, ||, etc.)
--! @return jsonb (never returns; always raises)
CREATE FUNCTION eql_v3.encrypted_domain_unsupported_jsonb(type_name text, operator_name text)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;

--! @brief Shared blocker helper returning text. Identical to
--!        encrypted_domain_unsupported_bool but typed for blockers shadowing
--!        the native #>> operator whose result is text.
--! @param type_name Domain type name (eql_v3.<T>*)
--! @param operator_name Operator symbol (#>>)
--! @return text (never returns; always raises)
CREATE FUNCTION eql_v3.encrypted_domain_unsupported_text(type_name text, operator_name text)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;

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
--! @return eql_v3.ore_block_256 ORE block composite, or NULL if input is null
--! @note Inlinable `LANGUAGE sql` IMMUTABLE form (no `SET search_path`) so the
--!   planner can fold this per-encrypted-value helper into the calling query.
--!   This deliberately diverges from the v2 plpgsql equivalent (intentionally
--!   left unchanged): the `CASE WHEN jsonb_typeof(val) = 'array'` guard only
--!   evaluates the array path for an array, so a non-array JSON scalar returns
--!   NULL here instead of raising. The sole caller (`ore_block_256`) only reaches
--!   this when `has_ore_block_256(val)` is true, which now requires `val->'ob'`
--!   to be a JSON array, so the non-array branch is unreachable in practice.
--!   An empty array (`ob: []`, what encrypting the empty string `""` produces)
--!   yields a non-NULL composite with an EMPTY `terms` array — NOT NULL terms.
--!   The `COALESCE` is load-bearing: `array_agg` over zero rows returns NULL, and
--!   NULL terms make the comparator return NULL (so an empty-text row silently
--!   drops out of ordered queries). An empty array instead engages the
--!   comparator's `cardinality = 0` guard, which sorts empty BEFORE every
--!   non-empty term. See issue #262 (pinned by T7).
CREATE FUNCTION eql_v3.jsonb_array_to_ore_block_256(val jsonb)
RETURNS eql_v3.ore_block_256
  IMMUTABLE
AS $$
  SELECT CASE WHEN jsonb_typeof(val) = 'array'
    THEN ROW(COALESCE(
      (
        SELECT array_agg(ROW(b)::eql_v3.ore_block_256_term)
        FROM unnest(eql_v3.jsonb_array_to_bytea_array(val)) AS b
      ),
      ARRAY[]::eql_v3.ore_block_256_term[]
    ))::eql_v3.ore_block_256
    ELSE NULL
  END;
$$ LANGUAGE sql;

--! @internal Mark this hand-written helper inline-critical so the post-install
--! pin_search_path pass leaves it unpinned (no `SET search_path`), preserving
--! SQL-function inlining. It takes a bare `jsonb` arg (not a jsonb-backed
--! encrypted DOMAIN), so the structural skip in tasks/pin_search_path.sql does
--! not recognise it; this marker is the documented manual opt-in.
COMMENT ON FUNCTION eql_v3.jsonb_array_to_ore_block_256(jsonb) IS
  'eql-inline-critical: per-encrypted-value ORE helper; must stay inlinable (unpinned search_path)';


--! @brief Extract ORE block index term from JSONB payload
--! @param val jsonb containing encrypted EQL payload
--! @return eql_v3.ore_block_256 ORE block index term
--! @throws Exception if 'ob' field is missing
CREATE FUNCTION eql_v3.ore_block_256(val jsonb)
  RETURNS eql_v3.ore_block_256
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    -- Declared STRICT: PostgreSQL returns NULL for a NULL argument without
    -- entering the body, so no explicit `val IS NULL` guard is needed.
    IF eql_v3.has_ore_block_256(val) THEN
      RETURN eql_v3.jsonb_array_to_ore_block_256(val->'ob');
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
CREATE FUNCTION eql_v3.has_ore_block_256(val jsonb)
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
--! @param a eql_v3.ore_block_256_term First ORE term
--! @param b eql_v3.ore_block_256_term Second ORE term
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
--! @throws Exception if ciphertexts are different lengths
--! @note Marked `IMMUTABLE` (the three `compare_ore_block_256_term(s)`
--!   overloads all are). This deliberately diverges from the v2 originals,
--!   which carry no volatility marker and so default to `VOLATILE`. The
--!   comparison is deterministic — its only crypto call, pgcrypto `encrypt()`,
--!   is itself `IMMUTABLE STRICT PARALLEL SAFE` — so `IMMUTABLE` lets the
--!   planner fold/cache these in ordering and index contexts. NOT `STRICT`:
--!   the NULL-handling branches below are load-bearing for the array overload.
CREATE FUNCTION eql_v3.compare_ore_block_256_term(a eql_v3.ore_block_256_term, b eql_v3.ore_block_256_term)
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
    -- This serves int4 (N=8, 408B), timestamp (N=12, 604B), and numeric
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
--! @param a eql_v3.ore_block_256_term[] First array
--! @param b eql_v3.ore_block_256_term[] Second array
--! @return integer -1/0/1, or NULL if either array is NULL
CREATE FUNCTION eql_v3.compare_ore_block_256_terms(a eql_v3.ore_block_256_term[], b eql_v3.ore_block_256_term[])
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

    cmp_result := eql_v3.compare_ore_block_256_term(a[1], b[1]);

    IF cmp_result = 0 THEN
      RETURN eql_v3.compare_ore_block_256_terms(a[2:array_length(a,1)], b[2:array_length(b,1)]);
    END IF;

    RETURN cmp_result;
  END
$$ LANGUAGE plpgsql;


--! @brief Compare ORE block composite types
--! @internal
--! @param a eql_v3.ore_block_256 First ORE block
--! @param b eql_v3.ore_block_256 Second ORE block
--! @return integer -1/0/1
CREATE FUNCTION eql_v3.compare_ore_block_256_terms(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v3.compare_ore_block_256_terms(a.terms, b.terms);
  END
$$ LANGUAGE plpgsql;

--! @file v3/sem/ore_block_256/operators.sql
--! @brief Comparison operators on eql_v3.ore_block_256.
--!
--! The six backing functions are inlinable single-statement SQL so the planner
--! can fold the eql_v3 comparison wrappers through to functional-index matching.

--! @brief Equality backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_256 Left operand
--! @param b eql_v3.ore_block_256 Right operand
--! @return boolean True if the ORE blocks are equal
--!
--! @see eql_v3.compare_ore_block_256_terms
CREATE FUNCTION eql_v3.ore_block_256_eq(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_256_terms(a, b) = 0
$$;

--! @brief Not-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_256 Left operand
--! @param b eql_v3.ore_block_256 Right operand
--! @return boolean True if the ORE blocks are not equal
--!
--! @see eql_v3.compare_ore_block_256_terms
CREATE FUNCTION eql_v3.ore_block_256_neq(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_256_terms(a, b) <> 0
$$;

--! @brief Less-than backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_256 Left operand
--! @param b eql_v3.ore_block_256 Right operand
--! @return boolean True if the left operand is less than the right operand
--!
--! @see eql_v3.compare_ore_block_256_terms
CREATE FUNCTION eql_v3.ore_block_256_lt(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_256_terms(a, b) = -1
$$;

--! @brief Less-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_256 Left operand
--! @param b eql_v3.ore_block_256 Right operand
--! @return boolean True if the left operand is less than or equal to the right operand
--!
--! @see eql_v3.compare_ore_block_256_terms
CREATE FUNCTION eql_v3.ore_block_256_lte(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_256_terms(a, b) != 1
$$;

--! @brief Greater-than backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_256 Left operand
--! @param b eql_v3.ore_block_256 Right operand
--! @return boolean True if the left operand is greater than the right operand
--!
--! @see eql_v3.compare_ore_block_256_terms
CREATE FUNCTION eql_v3.ore_block_256_gt(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_256_terms(a, b) = 1
$$;

--! @brief Greater-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_256 Left operand
--! @param b eql_v3.ore_block_256 Right operand
--! @return boolean True if the left operand is greater than or equal to the right operand
--!
--! @see eql_v3.compare_ore_block_256_terms
CREATE FUNCTION eql_v3.ore_block_256_gte(a eql_v3.ore_block_256, b eql_v3.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_256_terms(a, b) != -1
$$;


--! @brief = operator for ORE block types
--!
--! COMMUTATOR is the operator itself: equality is symmetric. Required for the
--! MERGES flag — without it the planner raises "could not find commutator" the
--! first time an ore_block equality is used as a join qual (e.g. via the inlined
--! eql_v3.<T>_ord_ore equality wrappers).
CREATE OPERATOR = (
  FUNCTION=eql_v3.ore_block_256_eq,
  LEFTARG=eql_v3.ore_block_256,
  RIGHTARG=eql_v3.ore_block_256,
  COMMUTATOR = =,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

--! @brief <> operator for ORE block types
CREATE OPERATOR <> (
  FUNCTION=eql_v3.ore_block_256_neq,
  LEFTARG=eql_v3.ore_block_256,
  RIGHTARG=eql_v3.ore_block_256,
  COMMUTATOR = <>,
  NEGATOR = =,
  RESTRICT = neqsel,
  JOIN = neqjoinsel,
  MERGES
);

--! @brief > operator for ORE block types
CREATE OPERATOR > (
  FUNCTION=eql_v3.ore_block_256_gt,
  LEFTARG=eql_v3.ore_block_256,
  RIGHTARG=eql_v3.ore_block_256,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief < operator for ORE block types
CREATE OPERATOR < (
  FUNCTION=eql_v3.ore_block_256_lt,
  LEFTARG=eql_v3.ore_block_256,
  RIGHTARG=eql_v3.ore_block_256,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief <= operator for ORE block types
CREATE OPERATOR <= (
  FUNCTION=eql_v3.ore_block_256_lte,
  LEFTARG=eql_v3.ore_block_256,
  RIGHTARG=eql_v3.ore_block_256,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief >= operator for ORE block types
CREATE OPERATOR >= (
  FUNCTION=eql_v3.ore_block_256_gte,
  LEFTARG=eql_v3.ore_block_256,
  RIGHTARG=eql_v3.ore_block_256,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

--! @file v3/sem/hmac_256/functions.sql
--! @brief HMAC-SHA256 index-term extraction from a jsonb payload (eql_v3 SEM).
--!
--! jsonb-only subset of src/hmac_256/functions.sql. The encrypted-column and
--! ste_vec-entry overloads are intentionally omitted — the eql_v3 scalar
--! domains extract from the jsonb payload directly via a cast to the domain.
--! (Doc comments deliberately avoid naming eql_v2 symbols so the
--! self-containment grep stays clean.)

--! @brief Extract HMAC-SHA256 index term from JSONB payload
--!
--! Inlinable single-statement SQL — the planner can fold this into the calling
--! query so functional hash/btree indexes built on `eql_v3.eq_term(col)`
--! (which calls this) engage structurally.
--!
--! @param val jsonb containing encrypted EQL payload
--! @return eql_v3.hmac_256 HMAC-SHA256 hash value, or NULL when `hm` is absent
CREATE FUNCTION eql_v3.hmac_256(val jsonb)
  RETURNS eql_v3.hmac_256
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (val ->> 'hm')::eql_v3.hmac_256
$$;


--! @brief Check if JSONB payload contains HMAC-SHA256 index term
--!
--! @param val jsonb containing encrypted EQL payload
--! @return boolean True if 'hm' field is present and non-null
CREATE FUNCTION eql_v3.has_hmac_256(val jsonb)
  RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (val ->> 'hm') IS NOT NULL
$$;

--! @file v3/sem/bloom_filter/functions.sql
--! @brief Extractor for the eql_v3 Bloom-filter SEM index term.
--!
--! jsonb-only subset of src/bloom_filter/functions.sql. The encrypted-column
--! overloads are intentionally omitted — the eql_v3 scalar domains extract from
--! the jsonb payload directly via a cast to the domain. (Doc comments
--! deliberately avoid naming eql_v2 symbols so the self-containment grep stays
--! clean.)

--! @brief Test whether a jsonb payload carries a Bloom-filter (`bf`) term.
--!
--! @param val jsonb The encrypted payload.
--! @return boolean True when the `bf` key is present and non-null.
--!
--! @internal Defined for parity with the eql_v3 SEM index-term predicates
--! (`has_hmac_256` / `has_ore_block_256`); it is not currently called by
--! the extractor below, which gates on value-shape inline, nor by the generated
--! domain CHECK, which tests `bf` presence via the envelope-key skeleton. Kept
--! as the canonical presence test for callers that need one.
CREATE FUNCTION eql_v3.has_bloom_filter(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN val ? 'bf' AND val ->> 'bf' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract the Bloom-filter index term from a jsonb payload.
--!
--! Inlinable single-statement SQL — the planner can fold this into the calling
--! query so the functional GIN index built on `eql_v3.match_term(col)` (which
--! calls this) engages structurally. Mirrors `eql_v3.hmac_256(jsonb)`: no RAISE
--! and no pinned `search_path`. Returns NULL when `bf` is absent or present but
--! not a json array, rather than raising. The `text_match` domain CHECK
--! guarantees the `bf` *key* is present but not that it is an array, so a
--! non-array `bf` (e.g. `{"bf": null}`) can reach here even on a typed value;
--! gating on `jsonb_typeof(...) = 'array'` returns NULL for that case — and for
--! raw jsonb outside the domain — instead of erroring inside
--! `jsonb_array_elements`. NULL, like the HMAC extractor, is the right answer. An
--! empty `bf` array yields an empty filter (contains nothing, contained by
--! everything), matching set-containment semantics.
--!
--! @param val jsonb The encrypted payload.
--! @return eql_v3.bloom_filter The `bf` array as a smallint[] domain value, or
--!   NULL when `bf` is absent or not a json array.
CREATE FUNCTION eql_v3.bloom_filter(val jsonb)
  RETURNS eql_v3.bloom_filter
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE WHEN jsonb_typeof(val -> 'bf') = 'array'
    THEN ARRAY(SELECT jsonb_array_elements(val -> 'bf'))::eql_v3.bloom_filter
  END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/int4/int4_types.sql
--! @brief Encrypted-domain types for int4.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.int4.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int4' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int4 AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int4_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int4_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int4_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int4_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int4_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int4_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int4_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int4_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int4_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_ord_functions.sql
--! @brief Functions for eql_v3.int4_ord.

--! @brief Index extractor for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int4_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.int4_ord) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.int4_ord) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.int4_ord) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.int4_ord) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.int4_ord) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.int4_ord) $$;

--! @brief Operator wrapper for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param selector text
--! @return eql_v3.int4_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.int4_ord, selector text)
RETURNS eql_v3.int4_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param selector integer
--! @return eql_v3.int4_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.int4_ord, selector integer)
RETURNS eql_v3.int4_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a jsonb
--! @param selector eql_v3.int4_ord
--! @return eql_v3.int4_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int4_ord)
RETURNS eql_v3.int4_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a jsonb
--! @param selector eql_v3.int4_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int4_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int4_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int4_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int4_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int4_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int4_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int4_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int4_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int4_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b eql_v3.int4_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4_ord, b eql_v3.int4_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a eql_v3.int4_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord.
--! @param a jsonb
--! @param b eql_v3.int4_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int4_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_ord_operators.sql
--! @brief Operators for eql_v3.int4_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = eql_v3.int4_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_eq_functions.sql
--! @brief Functions for eql_v3.int4_eq.

--! @brief Index extractor for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.int4_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.int4_eq) $$;

--! @brief Operator wrapper for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.int4_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.int4_eq) $$;

--! @brief Operator wrapper for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.int4_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param selector text
--! @return eql_v3.int4_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.int4_eq, selector text)
RETURNS eql_v3.int4_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param selector integer
--! @return eql_v3.int4_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.int4_eq, selector integer)
RETURNS eql_v3.int4_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param selector eql_v3.int4_eq
--! @return eql_v3.int4_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int4_eq)
RETURNS eql_v3.int4_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param selector eql_v3.int4_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int4_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int4_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int4_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int4_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int4_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int4_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int4_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int4_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int4_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b eql_v3.int4_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4_eq, b eql_v3.int4_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a eql_v3.int4_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_eq.
--! @param a jsonb
--! @param b eql_v3.int4_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int4_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/timestamptz/timestamptz_types.sql
--! @brief Encrypted-domain types for timestamptz.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.timestamptz.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'timestamptz' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.timestamptz AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.timestamptz_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'timestamptz_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.timestamptz_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.timestamptz_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'timestamptz_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.timestamptz_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.timestamptz_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'timestamptz_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.timestamptz_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_ord_ore_functions.sql
--! @brief Functions for eql_v3.timestamptz_ord_ore.

--! @brief Index extractor for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.timestamptz_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.timestamptz_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.timestamptz_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.timestamptz_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.timestamptz_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.timestamptz_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.timestamptz_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param selector text
--! @return eql_v3.timestamptz_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz_ord_ore, selector text)
RETURNS eql_v3.timestamptz_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param selector integer
--! @return eql_v3.timestamptz_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz_ord_ore, selector integer)
RETURNS eql_v3.timestamptz_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.timestamptz_ord_ore
--! @return eql_v3.timestamptz_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.timestamptz_ord_ore)
RETURNS eql_v3.timestamptz_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.timestamptz_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.timestamptz_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.timestamptz_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.timestamptz_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.timestamptz_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.timestamptz_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.timestamptz_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.timestamptz_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.timestamptz_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.timestamptz_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b eql_v3.timestamptz_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz_ord_ore, b eql_v3.timestamptz_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a eql_v3.timestamptz_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord_ore.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.timestamptz_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_ord_ore_operators.sql
--! @brief Operators for eql_v3.timestamptz_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = eql_v3.timestamptz_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_eq_functions.sql
--! @brief Functions for eql_v3.timestamptz_eq.

--! @brief Index extractor for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.timestamptz_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.timestamptz_eq) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.timestamptz_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.timestamptz_eq) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.timestamptz_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.timestamptz_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param selector text
--! @return eql_v3.timestamptz_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz_eq, selector text)
RETURNS eql_v3.timestamptz_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param selector integer
--! @return eql_v3.timestamptz_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz_eq, selector integer)
RETURNS eql_v3.timestamptz_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param selector eql_v3.timestamptz_eq
--! @return eql_v3.timestamptz_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.timestamptz_eq)
RETURNS eql_v3.timestamptz_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param selector eql_v3.timestamptz_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.timestamptz_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.timestamptz_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.timestamptz_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.timestamptz_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.timestamptz_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.timestamptz_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.timestamptz_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.timestamptz_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.timestamptz_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b eql_v3.timestamptz_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz_eq, b eql_v3.timestamptz_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a eql_v3.timestamptz_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_eq.
--! @param a jsonb
--! @param b eql_v3.timestamptz_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.timestamptz_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_ord_functions.sql
--! @brief Functions for eql_v3.timestamptz_ord.

--! @brief Index extractor for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.timestamptz_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.timestamptz_ord) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.timestamptz_ord) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.timestamptz_ord) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.timestamptz_ord) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.timestamptz_ord) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.timestamptz_ord) $$;

--! @brief Operator wrapper for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.timestamptz_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.timestamptz_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param selector text
--! @return eql_v3.timestamptz_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz_ord, selector text)
RETURNS eql_v3.timestamptz_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param selector integer
--! @return eql_v3.timestamptz_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz_ord, selector integer)
RETURNS eql_v3.timestamptz_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param selector eql_v3.timestamptz_ord
--! @return eql_v3.timestamptz_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.timestamptz_ord)
RETURNS eql_v3.timestamptz_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param selector eql_v3.timestamptz_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.timestamptz_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.timestamptz_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.timestamptz_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.timestamptz_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.timestamptz_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.timestamptz_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.timestamptz_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.timestamptz_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.timestamptz_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b eql_v3.timestamptz_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz_ord, b eql_v3.timestamptz_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a eql_v3.timestamptz_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz_ord.
--! @param a jsonb
--! @param b eql_v3.timestamptz_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.timestamptz_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_ord_operators.sql
--! @brief Operators for eql_v3.timestamptz_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = eql_v3.timestamptz_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/int2/int2_types.sql
--! @brief Encrypted-domain types for int2.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.int2.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int2' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int2 AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int2_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int2_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int2_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int2_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int2_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int2_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int2_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int2_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int2_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_ord_ore_functions.sql
--! @brief Functions for eql_v3.int2_ord_ore.

--! @brief Index extractor for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int2_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.int2_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.int2_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.int2_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.int2_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.int2_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.int2_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int2_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param selector text
--! @return eql_v3.int2_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.int2_ord_ore, selector text)
RETURNS eql_v3.int2_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param selector integer
--! @return eql_v3.int2_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.int2_ord_ore, selector integer)
RETURNS eql_v3.int2_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.int2_ord_ore
--! @return eql_v3.int2_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int2_ord_ore)
RETURNS eql_v3.int2_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.int2_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int2_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int2_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int2_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int2_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int2_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int2_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int2_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int2_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int2_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b eql_v3.int2_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2_ord_ore, b eql_v3.int2_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a eql_v3.int2_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int2_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int2_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_ord_functions.sql
--! @brief Functions for eql_v3.int2_ord.

--! @brief Index extractor for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int2_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.int2_ord) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.int2_ord) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.int2_ord) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.int2_ord) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.int2_ord) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.int2_ord) $$;

--! @brief Operator wrapper for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int2_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int2_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int2_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int2_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param selector text
--! @return eql_v3.int2_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.int2_ord, selector text)
RETURNS eql_v3.int2_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param selector integer
--! @return eql_v3.int2_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.int2_ord, selector integer)
RETURNS eql_v3.int2_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a jsonb
--! @param selector eql_v3.int2_ord
--! @return eql_v3.int2_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int2_ord)
RETURNS eql_v3.int2_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a jsonb
--! @param selector eql_v3.int2_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int2_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int2_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int2_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int2_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int2_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int2_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int2_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int2_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int2_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b eql_v3.int2_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2_ord, b eql_v3.int2_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a eql_v3.int2_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_ord.
--! @param a jsonb
--! @param b eql_v3.int2_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int2_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_ord_operators.sql
--! @brief Operators for eql_v3.int2_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = eql_v3.int2_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_functions.sql
--! @brief Functions for eql_v3.int2.

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int2)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param selector text
--! @return eql_v3.int2
CREATE FUNCTION eql_v3."->"(a eql_v3.int2, selector text)
RETURNS eql_v3.int2 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param selector integer
--! @return eql_v3.int2
CREATE FUNCTION eql_v3."->"(a eql_v3.int2, selector integer)
RETURNS eql_v3.int2 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param selector eql_v3.int2
--! @return eql_v3.int2
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int2)
RETURNS eql_v3.int2 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param selector eql_v3.int2
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int2)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int2, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int2, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int2, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int2, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int2, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int2, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int2, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int2, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b eql_v3.int2
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2, b eql_v3.int2)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a eql_v3.int2
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2.
--! @param a jsonb
--! @param b eql_v3.int2
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int2)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_ord_ore_operators.sql
--! @brief Operators for eql_v3.int2_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = eql_v3.int2_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/float8/float8_types.sql
--! @brief Encrypted-domain types for float8.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.float8.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float8' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float8 AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.float8_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float8_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float8_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.float8_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float8_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float8_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.float8_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float8_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float8_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_ord_ore_functions.sql
--! @brief Functions for eql_v3.float8_ord_ore.

--! @brief Index extractor for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.float8_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.float8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.float8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.float8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.float8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.float8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.float8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param selector text
--! @return eql_v3.float8_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.float8_ord_ore, selector text)
RETURNS eql_v3.float8_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param selector integer
--! @return eql_v3.float8_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.float8_ord_ore, selector integer)
RETURNS eql_v3.float8_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.float8_ord_ore
--! @return eql_v3.float8_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float8_ord_ore)
RETURNS eql_v3.float8_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.float8_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float8_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float8_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float8_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float8_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float8_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float8_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float8_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float8_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float8_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b eql_v3.float8_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8_ord_ore, b eql_v3.float8_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a eql_v3.float8_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float8_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float8_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_ord_ore_operators.sql
--! @brief Operators for eql_v3.float8_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = eql_v3.float8_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_ord_functions.sql
--! @brief Functions for eql_v3.float8_ord.

--! @brief Index extractor for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.float8_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.float8_ord) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.float8_ord) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.float8_ord) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.float8_ord) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.float8_ord) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.float8_ord) $$;

--! @brief Operator wrapper for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float8_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param selector text
--! @return eql_v3.float8_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.float8_ord, selector text)
RETURNS eql_v3.float8_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param selector integer
--! @return eql_v3.float8_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.float8_ord, selector integer)
RETURNS eql_v3.float8_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a jsonb
--! @param selector eql_v3.float8_ord
--! @return eql_v3.float8_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float8_ord)
RETURNS eql_v3.float8_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a jsonb
--! @param selector eql_v3.float8_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float8_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float8_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float8_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float8_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float8_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float8_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float8_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float8_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float8_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b eql_v3.float8_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8_ord, b eql_v3.float8_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a eql_v3.float8_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_ord.
--! @param a jsonb
--! @param b eql_v3.float8_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float8_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_functions.sql
--! @brief Functions for eql_v3.float8.

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param selector text
--! @return eql_v3.float8
CREATE FUNCTION eql_v3."->"(a eql_v3.float8, selector text)
RETURNS eql_v3.float8 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param selector integer
--! @return eql_v3.float8
CREATE FUNCTION eql_v3."->"(a eql_v3.float8, selector integer)
RETURNS eql_v3.float8 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param selector eql_v3.float8
--! @return eql_v3.float8
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float8)
RETURNS eql_v3.float8 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param selector eql_v3.float8
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float8)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float8, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float8, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float8, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float8, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float8, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float8, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float8, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float8, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b eql_v3.float8
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8, b eql_v3.float8)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a eql_v3.float8
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8.
--! @param a jsonb
--! @param b eql_v3.float8
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float8)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/date/date_types.sql
--! @brief Encrypted-domain types for date.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.date.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'date' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.date AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.date_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'date_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.date_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.date_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'date_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.date_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.date_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'date_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.date_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_ord_ore_functions.sql
--! @brief Functions for eql_v3.date_ord_ore.

--! @brief Index extractor for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.date_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.date_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.date_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.date_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.date_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.date_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.date_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.date_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param selector text
--! @return eql_v3.date_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.date_ord_ore, selector text)
RETURNS eql_v3.date_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param selector integer
--! @return eql_v3.date_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.date_ord_ore, selector integer)
RETURNS eql_v3.date_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.date_ord_ore
--! @return eql_v3.date_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.date_ord_ore)
RETURNS eql_v3.date_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.date_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.date_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.date_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.date_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.date_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.date_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.date_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.date_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.date_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.date_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b eql_v3.date_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date_ord_ore, b eql_v3.date_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a eql_v3.date_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord_ore.
--! @param a jsonb
--! @param b eql_v3.date_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.date_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_eq_functions.sql
--! @brief Functions for eql_v3.date_eq.

--! @brief Index extractor for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.date_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.date_eq) $$;

--! @brief Operator wrapper for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.date_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.date_eq) $$;

--! @brief Operator wrapper for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.date_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.date_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.date_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param selector text
--! @return eql_v3.date_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.date_eq, selector text)
RETURNS eql_v3.date_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param selector integer
--! @return eql_v3.date_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.date_eq, selector integer)
RETURNS eql_v3.date_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param selector eql_v3.date_eq
--! @return eql_v3.date_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.date_eq)
RETURNS eql_v3.date_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param selector eql_v3.date_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.date_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.date_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.date_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.date_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.date_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.date_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.date_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.date_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.date_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b eql_v3.date_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date_eq, b eql_v3.date_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a eql_v3.date_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_eq.
--! @param a jsonb
--! @param b eql_v3.date_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.date_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_functions.sql
--! @brief Functions for eql_v3.date.

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.date)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param selector text
--! @return eql_v3.date
CREATE FUNCTION eql_v3."->"(a eql_v3.date, selector text)
RETURNS eql_v3.date IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param selector integer
--! @return eql_v3.date
CREATE FUNCTION eql_v3."->"(a eql_v3.date, selector integer)
RETURNS eql_v3.date IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param selector eql_v3.date
--! @return eql_v3.date
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.date)
RETURNS eql_v3.date IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param selector eql_v3.date
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.date)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.date, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.date, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.date, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.date, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.date, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.date, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.date, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.date, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b eql_v3.date
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date, b eql_v3.date)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a eql_v3.date
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date.
--! @param a jsonb
--! @param b eql_v3.date
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.date)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_ord_ore_operators.sql
--! @brief Operators for eql_v3.date_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = eql_v3.date_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/numeric/numeric_types.sql
--! @brief Encrypted-domain types for numeric.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.numeric.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'numeric' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.numeric AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.numeric_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'numeric_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.numeric_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.numeric_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'numeric_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.numeric_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.numeric_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'numeric_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.numeric_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_ord_ore_functions.sql
--! @brief Functions for eql_v3.numeric_ord_ore.

--! @brief Index extractor for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.numeric_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.numeric_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.numeric_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.numeric_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.numeric_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.numeric_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.numeric_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param selector text
--! @return eql_v3.numeric_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric_ord_ore, selector text)
RETURNS eql_v3.numeric_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param selector integer
--! @return eql_v3.numeric_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric_ord_ore, selector integer)
RETURNS eql_v3.numeric_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.numeric_ord_ore
--! @return eql_v3.numeric_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.numeric_ord_ore)
RETURNS eql_v3.numeric_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.numeric_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.numeric_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.numeric_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.numeric_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.numeric_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.numeric_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.numeric_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.numeric_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.numeric_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.numeric_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b eql_v3.numeric_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric_ord_ore, b eql_v3.numeric_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a eql_v3.numeric_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord_ore.
--! @param a jsonb
--! @param b eql_v3.numeric_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.numeric_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_eq_functions.sql
--! @brief Functions for eql_v3.numeric_eq.

--! @brief Index extractor for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.numeric_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.numeric_eq) $$;

--! @brief Operator wrapper for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.numeric_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.numeric_eq) $$;

--! @brief Operator wrapper for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.numeric_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.numeric_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param selector text
--! @return eql_v3.numeric_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric_eq, selector text)
RETURNS eql_v3.numeric_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param selector integer
--! @return eql_v3.numeric_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric_eq, selector integer)
RETURNS eql_v3.numeric_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param selector eql_v3.numeric_eq
--! @return eql_v3.numeric_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.numeric_eq)
RETURNS eql_v3.numeric_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param selector eql_v3.numeric_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.numeric_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.numeric_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.numeric_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.numeric_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.numeric_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.numeric_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.numeric_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.numeric_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.numeric_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b eql_v3.numeric_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric_eq, b eql_v3.numeric_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a eql_v3.numeric_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_eq.
--! @param a jsonb
--! @param b eql_v3.numeric_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.numeric_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_ord_ore_operators.sql
--! @brief Operators for eql_v3.numeric_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = eql_v3.numeric_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/bool/bool_types.sql
--! @brief Encrypted-domain types for bool.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.bool.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'bool' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.bool AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/bool/bool_functions.sql
--! @brief Functions for eql_v3.bool.

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.bool, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.bool, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.bool)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param selector text
--! @return eql_v3.bool
CREATE FUNCTION eql_v3."->"(a eql_v3.bool, selector text)
RETURNS eql_v3.bool IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param selector integer
--! @return eql_v3.bool
CREATE FUNCTION eql_v3."->"(a eql_v3.bool, selector integer)
RETURNS eql_v3.bool IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param selector eql_v3.bool
--! @return eql_v3.bool
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.bool)
RETURNS eql_v3.bool IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.bool, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.bool, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param selector eql_v3.bool
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.bool)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.bool, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.bool, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.bool, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.bool, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.bool, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.bool, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.bool, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.bool, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.bool, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.bool, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.bool, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b eql_v3.bool
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.bool, b eql_v3.bool)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a eql_v3.bool
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.bool, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.bool.
--! @param a jsonb
--! @param b eql_v3.bool
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.bool)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.bool'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/int8/int8_types.sql
--! @brief Encrypted-domain types for int8.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.int8.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int8' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int8 AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int8_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int8_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int8_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int8_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int8_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int8_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.int8_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'int8_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.int8_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_functions.sql
--! @brief Functions for eql_v3.int8.

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int8)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param selector text
--! @return eql_v3.int8
CREATE FUNCTION eql_v3."->"(a eql_v3.int8, selector text)
RETURNS eql_v3.int8 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param selector integer
--! @return eql_v3.int8
CREATE FUNCTION eql_v3."->"(a eql_v3.int8, selector integer)
RETURNS eql_v3.int8 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param selector eql_v3.int8
--! @return eql_v3.int8
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int8)
RETURNS eql_v3.int8 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param selector eql_v3.int8
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int8)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int8, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int8, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int8, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int8, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int8, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int8, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int8, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int8, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b eql_v3.int8
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8, b eql_v3.int8)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a eql_v3.int8
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8.
--! @param a jsonb
--! @param b eql_v3.int8
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int8)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_ord_functions.sql
--! @brief Functions for eql_v3.int8_ord.

--! @brief Index extractor for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int8_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.int8_ord) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.int8_ord) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.int8_ord) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.int8_ord) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.int8_ord) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.int8_ord) $$;

--! @brief Operator wrapper for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int8_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int8_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param selector text
--! @return eql_v3.int8_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.int8_ord, selector text)
RETURNS eql_v3.int8_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param selector integer
--! @return eql_v3.int8_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.int8_ord, selector integer)
RETURNS eql_v3.int8_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a jsonb
--! @param selector eql_v3.int8_ord
--! @return eql_v3.int8_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int8_ord)
RETURNS eql_v3.int8_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a jsonb
--! @param selector eql_v3.int8_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int8_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int8_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int8_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int8_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int8_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int8_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int8_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int8_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int8_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b eql_v3.int8_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8_ord, b eql_v3.int8_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a eql_v3.int8_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord.
--! @param a jsonb
--! @param b eql_v3.int8_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int8_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/text/text_types.sql
--! @brief Encrypted-domain types for text.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.text.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'text' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.text AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.text_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'text_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.text_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.text_match.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'text_match' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.text_match AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'bf'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.text_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'text_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.text_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.text_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'text_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.text_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.text_search.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'text_search' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.text_search AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE ? 'ob'
        AND VALUE ? 'bf'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_ord_functions.sql
--! @brief Functions for eql_v3.text_ord.

--! @brief Index extractor for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.text_ord)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.text_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_ord) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_ord) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.text_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param selector text
--! @return eql_v3.text_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.text_ord, selector text)
RETURNS eql_v3.text_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param selector integer
--! @return eql_v3.text_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.text_ord, selector integer)
RETURNS eql_v3.text_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a jsonb
--! @param selector eql_v3.text_ord
--! @return eql_v3.text_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.text_ord)
RETURNS eql_v3.text_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a jsonb
--! @param selector eql_v3.text_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.text_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.text_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.text_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.text_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.text_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.text_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.text_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.text_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.text_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.text_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_ord_ore_functions.sql
--! @brief Functions for eql_v3.text_ord_ore.

--! @brief Index extractor for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.text_ord_ore)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.text_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_ord_ore) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_ord_ore) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param selector text
--! @return eql_v3.text_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.text_ord_ore, selector text)
RETURNS eql_v3.text_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param selector integer
--! @return eql_v3.text_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.text_ord_ore, selector integer)
RETURNS eql_v3.text_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.text_ord_ore
--! @return eql_v3.text_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.text_ord_ore)
RETURNS eql_v3.text_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.text_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.text_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.text_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.text_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.text_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.text_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.text_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.text_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.text_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.text_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.text_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_match_functions.sql
--! @brief Functions for eql_v3.text_match.

--! @brief Index extractor for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @return eql_v3.bloom_filter
CREATE FUNCTION eql_v3.match_term(a eql_v3.text_match)
RETURNS eql_v3.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.bloom_filter(a::jsonb) $$;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_match, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.text_match)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Operator wrapper for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_match, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b::eql_v3.text_match) $$;

--! @brief Operator wrapper for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a::eql_v3.text_match) @> eql_v3.match_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_match, b eql_v3.text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) <@ eql_v3.match_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_match, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) <@ eql_v3.match_term(b::eql_v3.text_match) $$;

--! @brief Operator wrapper for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.text_match)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a::eql_v3.text_match) <@ eql_v3.match_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param selector text
--! @return eql_v3.text_match
CREATE FUNCTION eql_v3."->"(a eql_v3.text_match, selector text)
RETURNS eql_v3.text_match IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param selector integer
--! @return eql_v3.text_match
CREATE FUNCTION eql_v3."->"(a eql_v3.text_match, selector integer)
RETURNS eql_v3.text_match IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param selector eql_v3.text_match
--! @return eql_v3.text_match
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.text_match)
RETURNS eql_v3.text_match IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_match, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_match, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param selector eql_v3.text_match
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.text_match)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.text_match, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.text_match, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.text_match, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.text_match, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.text_match, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.text_match, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.text_match, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_match, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_match, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_match, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.text_match, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b eql_v3.text_match
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_match, b eql_v3.text_match)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a eql_v3.text_match
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_match, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_match.
--! @param a jsonb
--! @param b eql_v3.text_match
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.text_match)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_match'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_search_functions.sql
--! @brief Functions for eql_v3.text_search.

--! @brief Index extractor for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.text_search)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.text_search)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Index extractor for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @return eql_v3.bloom_filter
CREATE FUNCTION eql_v3.match_term(a eql_v3.text_search)
RETURNS eql_v3.bloom_filter
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.bloom_filter(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_search) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_search) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_search) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_search) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_search) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_search) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) @> eql_v3.match_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a::eql_v3.text_search) @> eql_v3.match_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_search, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) <@ eql_v3.match_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_search, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a) <@ eql_v3.match_term(b::eql_v3.text_search) $$;

--! @brief Operator wrapper for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.text_search)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.match_term(a::eql_v3.text_search) <@ eql_v3.match_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param selector text
--! @return eql_v3.text_search
CREATE FUNCTION eql_v3."->"(a eql_v3.text_search, selector text)
RETURNS eql_v3.text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param selector integer
--! @return eql_v3.text_search
CREATE FUNCTION eql_v3."->"(a eql_v3.text_search, selector integer)
RETURNS eql_v3.text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a jsonb
--! @param selector eql_v3.text_search
--! @return eql_v3.text_search
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.text_search)
RETURNS eql_v3.text_search IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_search, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_search, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a jsonb
--! @param selector eql_v3.text_search
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.text_search)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.text_search, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.text_search, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.text_search, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.text_search, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.text_search, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.text_search, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_search, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_search, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.text_search, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b eql_v3.text_search
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_search, b eql_v3.text_search)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a eql_v3.text_search
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_search, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_search.
--! @param a jsonb
--! @param b eql_v3.text_search
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.text_search)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_search'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_eq_functions.sql
--! @brief Functions for eql_v3.text_eq.

--! @brief Index extractor for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.text_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.text_eq) $$;

--! @brief Operator wrapper for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.text_eq) $$;

--! @brief Operator wrapper for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.text_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.text_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param selector text
--! @return eql_v3.text_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.text_eq, selector text)
RETURNS eql_v3.text_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param selector integer
--! @return eql_v3.text_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.text_eq, selector integer)
RETURNS eql_v3.text_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param selector eql_v3.text_eq
--! @return eql_v3.text_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.text_eq)
RETURNS eql_v3.text_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param selector eql_v3.text_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.text_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.text_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.text_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.text_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.text_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.text_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.text_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.text_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.text_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b eql_v3.text_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_eq, b eql_v3.text_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a eql_v3.text_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text_eq.
--! @param a jsonb
--! @param b eql_v3.text_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.text_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_ord_ore_operators.sql
--! @brief Operators for eql_v3.text_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = eql_v3.text_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_ord_operators.sql
--! @brief Operators for eql_v3.text_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.text_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_ord, RIGHTARG = eql_v3.text_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file v3/scalars/float4/float4_types.sql
--! @brief Encrypted-domain types for float4.

DO $$
BEGIN
  --! @brief Encrypted domain eql_v3.float4.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float4' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float4 AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.float4_eq.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float4_eq' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float4_eq AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'hm'
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.float4_ord_ore.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float4_ord_ore' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float4_ord_ore AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;

  --! @brief Encrypted domain eql_v3.float4_ord.
  IF NOT EXISTS (
    SELECT 1 FROM pg_type
    WHERE typname = 'float4_ord' AND typnamespace = 'eql_v3'::regnamespace
  ) THEN
    CREATE DOMAIN eql_v3.float4_ord AS jsonb
      CHECK (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE ? 'v'
        AND VALUE ? 'i'
        AND VALUE ? 'c'
        AND VALUE ? 'ob'
        AND jsonb_typeof(VALUE -> 'ob') = 'array'
        AND jsonb_array_length(VALUE -> 'ob') > 0
        AND VALUE->>'v' = '2'
      );
  END IF;
END
$$;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_ord_ore_functions.sql
--! @brief Functions for eql_v3.float4_ord_ore.

--! @brief Index extractor for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.float4_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.float4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.float4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.float4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.float4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.float4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.float4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param selector text
--! @return eql_v3.float4_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.float4_ord_ore, selector text)
RETURNS eql_v3.float4_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param selector integer
--! @return eql_v3.float4_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.float4_ord_ore, selector integer)
RETURNS eql_v3.float4_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.float4_ord_ore
--! @return eql_v3.float4_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float4_ord_ore)
RETURNS eql_v3.float4_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.float4_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float4_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float4_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float4_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float4_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float4_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float4_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float4_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float4_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float4_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b eql_v3.float4_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4_ord_ore, b eql_v3.float4_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a eql_v3.float4_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.float4_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float4_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_eq_functions.sql
--! @brief Functions for eql_v3.float4_eq.

--! @brief Index extractor for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.float4_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.float4_eq) $$;

--! @brief Operator wrapper for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.float4_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.float4_eq) $$;

--! @brief Operator wrapper for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float4_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.float4_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float4_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param selector text
--! @return eql_v3.float4_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.float4_eq, selector text)
RETURNS eql_v3.float4_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param selector integer
--! @return eql_v3.float4_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.float4_eq, selector integer)
RETURNS eql_v3.float4_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param selector eql_v3.float4_eq
--! @return eql_v3.float4_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float4_eq)
RETURNS eql_v3.float4_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param selector eql_v3.float4_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float4_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float4_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float4_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float4_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float4_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float4_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float4_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float4_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float4_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b eql_v3.float4_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4_eq, b eql_v3.float4_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a eql_v3.float4_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_eq.
--! @param a jsonb
--! @param b eql_v3.float4_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float4_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_ord_functions.sql
--! @brief Functions for eql_v3.float4_ord.

--! @brief Index extractor for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.float4_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.float4_ord) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.float4_ord) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.float4_ord) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.float4_ord) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.float4_ord) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.float4_ord) $$;

--! @brief Operator wrapper for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float4_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.float4_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float4_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param selector text
--! @return eql_v3.float4_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.float4_ord, selector text)
RETURNS eql_v3.float4_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param selector integer
--! @return eql_v3.float4_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.float4_ord, selector integer)
RETURNS eql_v3.float4_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a jsonb
--! @param selector eql_v3.float4_ord
--! @return eql_v3.float4_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float4_ord)
RETURNS eql_v3.float4_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a jsonb
--! @param selector eql_v3.float4_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float4_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float4_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float4_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float4_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float4_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float4_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float4_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float4_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float4_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b eql_v3.float4_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4_ord, b eql_v3.float4_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a eql_v3.float4_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4_ord.
--! @param a jsonb
--! @param b eql_v3.float4_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float4_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_ord_ore_operators.sql
--! @brief Operators for eql_v3.float4_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = eql_v3.float4_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_ord_operators.sql
--! @brief Operators for eql_v3.float4_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = eql_v3.float4_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_ord
);

--! @file v3/sem/ore_cllw/types.sql
--! @brief CLLW ORE index term type for STE-vec range queries (eql_v3 SEM)
--!
--! Composite type for CLLW (Copyless Logarithmic Width) Order-Revealing
--! Encryption. The ciphertext is stored in the `oc` field of encrypted data
--! payloads (Standard-mode `ste_vec` elements). Used by the range operators
--! (`<`, `<=`, `>`, `>=`) when an sv element carries an `oc` term.
--!
--! The wire-format `oc` value is a hex string with a leading domain-tag byte
--! (`0x00` numeric, `0x01` string) followed by the CLLW ciphertext. The
--! decoded `bytes` field carries the full byte string including the tag — the
--! comparator is variable-length capable, so numeric and string values within
--! the same column order correctly: the domain tag separates the ranges
--! (numeric < string) and the within-domain comparison falls through to the
--! CLLW per-byte protocol.
--!
--! @note This is a transient type used only during query execution.
--! @see eql_v3.compare_ore_cllw_term
CREATE TYPE eql_v3.ore_cllw AS (
  bytes bytea
);

--! @file v3/sem/ore_cllw/functions.sql
--! @brief CLLW ORE index-term extraction and comparison (eql_v3 SEM).

--! @brief Extract CLLW ORE index term from raw jsonb
--!
--! Returns the CLLW ORE ciphertext from the `oc` field of a single sv element
--! supplied as raw jsonb. Inlinable single-statement SQL — the planner folds
--! the body into the calling query.
--!
--! **Missing-`oc` semantics**: returns SQL-level NULL (not a composite with
--! NULL bytes) when `oc` is absent, so btree's NULL handling filters those
--! rows from range queries.
--!
--! @param val jsonb An object carrying an `oc` field
--! @return eql_v3.ore_cllw Composite carrying the CLLW ciphertext, or NULL
--!         when the `oc` field is absent.
--! @see eql_v3.has_ore_cllw
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw(val jsonb)
  RETURNS eql_v3.ore_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE WHEN val ->> 'oc' IS NULL THEN NULL
              ELSE ROW(decode(val ->> 'oc', 'hex'))::eql_v3.ore_cllw
         END
$$;

COMMENT ON FUNCTION eql_v3.ore_cllw(jsonb) IS
  'eql-inline-critical: raw-jsonb CLLW extractor; must stay inlinable (unpinned search_path)';

--! @brief Check if a raw jsonb value contains a CLLW ORE index term
--! @param val jsonb An object that may carry an `oc` field
--! @return boolean True if `oc` field is present and non-null
CREATE FUNCTION eql_v3.has_ore_cllw(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT val ->> 'oc' IS NOT NULL
$$;

COMMENT ON FUNCTION eql_v3.has_ore_cllw(jsonb) IS
  'eql-inline-critical: raw-jsonb CLLW presence helper; must stay inlinable (unpinned search_path)';

--! @brief CLLW per-byte comparison helper
--! @internal
--!
--! Byte-by-byte comparison implementing the CLLW order-revealing protocol.
--! Identify the index of the first differing byte; if `(y_byte + 1) == x_byte`
--! (mod 256) there, then x > y; otherwise x < y. Equal inputs return 0. Inputs
--! MUST be the same length (the caller guarantees this). Stays `LANGUAGE
--! plpgsql` — the per-byte loop can't be a single inlinable SQL expression.
--!
--! @param a bytea First CLLW ciphertext slice
--! @param b bytea Second CLLW ciphertext slice
--! @return integer -1, 0, or 1
--! @throws Exception if inputs are different lengths
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.compare_ore_cllw_term_bytes(a bytea, b bytea)
RETURNS int
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    len_a INT;
    len_b INT;
    i INT;
    first_diff INT := 0;
BEGIN

    len_a := LENGTH(a);
    len_b := LENGTH(b);

    IF len_a != len_b THEN
      RAISE EXCEPTION 'ore_cllw index terms are not the same length';
    END IF;

    FOR i IN 1..len_a LOOP
        IF first_diff = 0 AND get_byte(a, i - 1) != get_byte(b, i - 1) THEN
            first_diff := i;
        END IF;
    END LOOP;

    IF first_diff = 0 THEN
        RETURN 0;
    END IF;

    IF ((get_byte(b, first_diff - 1) + 1) & 255) = get_byte(a, first_diff - 1) THEN
        RETURN 1;
    ELSE
        RETURN -1;
    END IF;
END;
$$ LANGUAGE plpgsql;

--! @brief Variable-length CLLW ORE term comparison
--! @internal
--!
--! Three-way comparison of two CLLW ORE ciphertext terms of potentially
--! different lengths. Compares the shared prefix via the CLLW per-byte
--! protocol; on equal prefixes, the shorter input sorts first. The leading
--! domain-tag byte makes numeric (`0x00`) sort before string (`0x01`). Stays
--! `LANGUAGE plpgsql` because it dispatches to `compare_ore_cllw_term_bytes`.
--!
--! btree filters NULL composites at the row level, so this should never see a
--! NULL composite under normal operation; the IS-NULL guard returns NULL
--! defensively. A non-NULL composite with NULL `bytes` is a contract violation
--! — the extractor returns SQL NULL (not ROW(NULL)) on missing `oc`, so raise
--! loudly rather than silently misorder.
--!
--! @param a eql_v3.ore_cllw First term
--! @param b eql_v3.ore_cllw Second term
--! @return integer -1, 0, or 1; NULL if either composite is NULL
--! @throws Exception if either composite has a NULL `bytes` field
--! @see eql_v3.compare_ore_cllw_term_bytes
CREATE FUNCTION eql_v3.compare_ore_cllw_term(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
RETURNS int
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    len_a INT;
    len_b INT;
    common_len INT;
    cmp_result INT;
BEGIN
    -- The `::text` cast is load-bearing, not a stylistic choice. For the
    -- single-field `ore_cllw` composite, `ROW(NULL)::ore_cllw IS NULL` is TRUE
    -- but `(ROW(NULL)::ore_cllw)::text IS NULL` is FALSE. Casting to text first
    -- means a NULL-component composite falls THROUGH to the RAISE below (the
    -- extractor-invariant violation) instead of silently returning NULL and
    -- masking it. A plain `a IS NULL` would reintroduce that masking bug.
    IF a::text IS NULL OR b::text IS NULL THEN
      RETURN NULL;
    END IF;

    IF a.bytes IS NULL OR b.bytes IS NULL THEN
      RAISE EXCEPTION 'eql_v3.compare_ore_cllw_term: composite has NULL bytes field — extractor invariant violated. Check that the index expression uses eql_v3.ore_cllw(...) and not a hand-crafted ROW(NULL).';
    END IF;

    len_a := LENGTH(a.bytes);
    len_b := LENGTH(b.bytes);

    IF len_a = 0 AND len_b = 0 THEN
        RETURN 0;
    ELSIF len_a = 0 THEN
        RETURN -1;
    ELSIF len_b = 0 THEN
        RETURN 1;
    END IF;

    IF len_a < len_b THEN
        common_len := len_a;
    ELSE
        common_len := len_b;
    END IF;

    cmp_result := eql_v3.compare_ore_cllw_term_bytes(
      SUBSTRING(a.bytes FROM 1 FOR common_len),
      SUBSTRING(b.bytes FROM 1 FOR common_len)
    );

    IF cmp_result = -1 THEN
        RETURN -1;
    ELSIF cmp_result = 1 THEN
        RETURN 1;
    END IF;

    IF len_a < len_b THEN
        RETURN -1;
    ELSIF len_a > len_b THEN
        RETURN 1;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;

--! @file v3/jsonb/types.sql
--! @brief Domain types for the eql_v3 encrypted-JSONB (SteVec) surface.
--!
--! Three jsonb-backed domains (none over another domain — operators resolve
--! against the ultimate base type jsonb, so the native-jsonb firewall in
--! blockers.sql can attach):
--!   - eql_v3.json     — storage/root: an EQL envelope object ({i, v, ...}).
--!   - eql_v3.ste_vec_entry — a single sv element (returned by `->`).
--!   - eql_v3.ste_vec_query  — a containment needle (sv elements, no ciphertext).

--! @brief Validate a single SteVec entry payload.
--! @internal
--! @param val jsonb Candidate entry payload.
--! @return boolean True when `val` is an sv entry with string `s`, string `c`,
--!         and exactly one string deterministic term (`hm` XOR `oc`).
CREATE FUNCTION eql_v3.is_valid_ste_vec_entry_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND jsonb_typeof(val -> 's') = 'string'
     AND jsonb_typeof(val -> 'c') = 'string'
     AND (
       (jsonb_typeof(val -> 'hm') = 'string' AND NOT (val ? 'oc'))
       OR
       (jsonb_typeof(val -> 'oc') = 'string' AND NOT (val ? 'hm'))
     ),
    false
  )
$$;

--! @brief Validate a SteVec containment query payload.
--! @internal
--! @param val jsonb Candidate query payload.
--! @return boolean True when `val` is `{"sv":[...]}` and every element carries
--!         string `s`, no ciphertext, and exactly one string term (`hm` XOR
--!         `oc`).
CREATE FUNCTION eql_v3.is_valid_ste_vec_query_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND jsonb_typeof(val -> 'sv') = 'array'
     AND NOT EXISTS (
       SELECT 1
       FROM jsonb_array_elements(
         CASE WHEN jsonb_typeof(val -> 'sv') = 'array' THEN val -> 'sv' ELSE '[]'::jsonb END
       ) AS elem
       WHERE NOT COALESCE((
         jsonb_typeof(elem) = 'object'
         AND jsonb_typeof(elem -> 's') = 'string'
         AND NOT (elem ? 'c')
         AND (
           (jsonb_typeof(elem -> 'hm') = 'string' AND NOT (elem ? 'oc'))
           OR
           (jsonb_typeof(elem -> 'oc') = 'string' AND NOT (elem ? 'hm'))
         )
       ), false)
     ),
    false
  )
$$;

--! @brief Validate a root SteVec document payload.
--! @internal
--! @param val jsonb Candidate document payload.
--! @return boolean True when `val` is an encrypted document envelope with
--!         `v = 2`, `i`, an `sv` array, and valid sv entry elements.
CREATE FUNCTION eql_v3.is_valid_ste_vec_document_payload(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT COALESCE(
    jsonb_typeof(val) = 'object'
     AND val ? 'v'
     AND val ->> 'v' = '2'
     AND val ? 'i'
     AND jsonb_typeof(val -> 'sv') = 'array'
     AND NOT EXISTS (
       SELECT 1
       FROM jsonb_array_elements(
         CASE WHEN jsonb_typeof(val -> 'sv') = 'array' THEN val -> 'sv' ELSE '[]'::jsonb END
       ) AS elem
       WHERE NOT eql_v3.is_valid_ste_vec_entry_payload(elem)
     ),
    false
  )
$$;

--! @brief Storage/root domain for an encrypted JSONB column.
--!
--! CHECK: a JSON object carrying the EQL envelope (`v = 2` version and `i` index
--! metadata). Root `c` is intentionally NOT required — an sv-array root payload
--! is `{i, v, sv}` with no root ciphertext. The CHECK now also requires an `sv`
--! array, so the domain accepts only SteVec **document** payloads and rejects
--! encrypted *scalar* payloads (which carry `c`/`hm`/`ob` but no `sv`) — this is
--! what keeps `eql_v3.json` a typed document domain rather than a generic
--! encrypted envelope. The firewall in blockers.sql attaches to this domain to
--! stop native jsonb operators from reaching a column value.
--!
--! @note Constructing from inline JSON uses the standard DOMAIN cast:
--!       `'{"i":{},"v":2,"sv":[...]}'::eql_v3.json`.
CREATE DOMAIN eql_v3.json AS jsonb
  CHECK (
    eql_v3.is_valid_ste_vec_document_payload(VALUE)
  );

--! @brief Domain type for an individual sv element.
--!
--! A single element inside an `sv` array: a JSON object that carries a selector
--! (`s`), a ciphertext (`c`), and **exactly one** of `hm` (HMAC-256, for
--! hash-equality) or `oc` (CLLW ORE, for ordered queries) — they are mutually
--! exclusive. This is the type returned by `->` and accepted by the per-entry
--! extractors `eql_v3.eq_term` / `eql_v3.ore_cllw`. Extra fields (`a`, root
--! `i`/`v` merged in by `->`) are allowed.
--!
--! @see src/v3/jsonb/operators.sql
CREATE DOMAIN eql_v3.ste_vec_entry AS jsonb
  CHECK (
    eql_v3.is_valid_ste_vec_entry_payload(VALUE)
  );

--! @brief Domain type for an STE-vec containment needle.
--!
--! A query-shaped payload `{"sv":[...]}` whose elements carry selector + index
--! term but **never** a ciphertext (`c`). Each element must carry `s` and
--! exactly one deterministic term (`hm` XOR `oc`). Typing the needle this way
--! stops selector-only needles from casting and matching every row via bare
--! `jsonb @>`.
--!
--! @note Construct from inline JSON via the DOMAIN cast:
--!       `'{"sv":[{"s":"<sel>","hm":"<hm>"}]}'::eql_v3.ste_vec_query`.
--! @see eql_v3.to_ste_vec_query
CREATE DOMAIN eql_v3.ste_vec_query AS jsonb
  CHECK (
    eql_v3.is_valid_ste_vec_query_payload(VALUE)
  );

--! @brief Convert an eql_v3.json to a ste_vec_query needle.
--!
--! Normalises each sv element down to the matching-relevant fields: `s` plus
--! exactly one of `hm` / `oc`. Other fields (`c`, `a`, `i`/`v`, anything else)
--! are stripped. This is the canonical needle shape for `@>` containment.
--! Designed for use as a functional GIN index expression:
--!   `GIN (eql_v3.to_ste_vec_query(col)::jsonb jsonb_path_ops)`.
--!
--! @param e eql_v3.json Source encrypted payload
--! @return eql_v3.ste_vec_query Query-shaped needle, sv elements normalised.
--! @see eql_v3.ste_vec_query
CREATE FUNCTION eql_v3.to_ste_vec_query(e eql_v3.json)
  RETURNS eql_v3.ste_vec_query
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT jsonb_build_object(
    'sv',
    coalesce(
      (SELECT jsonb_agg(
                jsonb_strip_nulls(
                  jsonb_build_object(
                    's',  elem -> 's',
                    'hm', elem -> 'hm',
                    'oc', elem -> 'oc'
                  )
                )
              )
       FROM jsonb_array_elements(e::jsonb -> 'sv') AS elem),
      '[]'::jsonb
    )
  )::eql_v3.ste_vec_query
$$;

CREATE CAST (eql_v3.json AS eql_v3.ste_vec_query)
  WITH FUNCTION eql_v3.to_ste_vec_query
  AS ASSIGNMENT;

--! @file v3/jsonb/functions.sql
--! @brief Extractors, containment engine, and path/array functions for the
--!        eql_v3 encrypted-JSONB (SteVec) surface.
--!
--! `selector` parameters here are *encrypted-side* selector hashes — the
--! deterministic hash the crypto layer emits in the `s` field of each sv
--! element. Plaintext JSONPaths are never accepted at runtime.

------------------------------------------------------------------------------
-- Envelope helpers (eql_v3 owns these; jsonb-only)
------------------------------------------------------------------------------

--! @brief Extract metadata (i, v) from a raw jsonb encrypted value.
--! @param val jsonb encrypted EQL payload
--! @return jsonb Metadata object with `i` and `v` fields.
CREATE FUNCTION eql_v3.meta_data(val jsonb)
  RETURNS jsonb
  IMMUTABLE STRICT PARALLEL SAFE
  LANGUAGE SQL
AS $$
  SELECT jsonb_build_object('i', val->'i', 'v', val->'v');
$$;

COMMENT ON FUNCTION eql_v3.meta_data(jsonb) IS
  'eql-inline-critical: raw-jsonb envelope helper used by v3 jsonb wrappers; must stay inlinable (unpinned search_path)';

--! @brief Extract ciphertext (c) from a raw jsonb encrypted value.
--! @param val jsonb encrypted EQL payload
--! @return text Base64-encoded ciphertext.
--! @throws Exception if `c` is absent.
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
--! @param entry eql_v3.ste_vec_entry
--! @return text The selector value.
CREATE FUNCTION eql_v3.selector(entry eql_v3.ste_vec_entry)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 's'
$$;

------------------------------------------------------------------------------
-- Equality-term extractor (XOR-aware: coalesce(hm, oc))
------------------------------------------------------------------------------

--! @brief XOR-aware equality term extractor for eql_v3.ste_vec_entry.
--!
--! Returns the bytea of whichever deterministic term the sv entry carries —
--! `hm` (HMAC-256) or `oc` (CLLW ORE). The two byte distributions are disjoint
--! by construction, so byte equality on the coalesce is unambiguous. Canonical
--! equality extractor used by `=` / `<>` on ste_vec_entry.
--!
--! @param entry eql_v3.ste_vec_entry
--! @return bytea Decoded `hm` or `oc` bytes (NULL if entry is NULL).
CREATE FUNCTION eql_v3.eq_term(entry eql_v3.ste_vec_entry)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT decode(coalesce(entry ->> 'hm', entry ->> 'oc'), 'hex')
$$;

------------------------------------------------------------------------------
-- ORE CLLW per-entry overloads (live here so sem/ore_cllw stays a leaf)
------------------------------------------------------------------------------

--! @brief Extract CLLW ORE index term from a ste_vec entry.
--!
--! `oc` is only ever present on an sv element, never at a root encrypted value,
--! so the typed overload accepts eql_v3.ste_vec_entry. Returns SQL NULL when
--! `oc` is absent (btree NULL-filters such rows from range queries).
--!
--! @param entry eql_v3.ste_vec_entry
--! @return eql_v3.ore_cllw Composite carrying the CLLW ciphertext, or NULL.
--! @see eql_v3.has_ore_cllw
CREATE FUNCTION eql_v3.ore_cllw(entry eql_v3.ste_vec_entry)
  RETURNS eql_v3.ore_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE WHEN entry ->> 'oc' IS NULL THEN NULL
              ELSE ROW(decode(entry ->> 'oc', 'hex'))::eql_v3.ore_cllw
         END
$$;

--! @brief Check if a ste_vec entry contains a CLLW ORE index term.
--! @param entry eql_v3.ste_vec_entry
--! @return boolean True if `oc` is present and non-null.
CREATE FUNCTION eql_v3.has_ore_cllw(entry eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 'oc' IS NOT NULL
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
CREATE FUNCTION eql_v3.is_ste_vec_array(val jsonb)
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

--! @brief Extract deterministic search fields (s, hm, oc, op) per sv element.
--!
--! Excludes non-deterministic ciphertext so PostgreSQL's native jsonb `@>` can
--! compare for containment. Use for GIN indexes and containment queries.
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
    WHERE kv.key IN ('s', 'hm', 'oc', 'op')
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
--! Match = selector equal AND eq_term equal (byte-equality over coalesce(hm,
--! oc)). This collapses the v2 hm/oc CASE: under the XOR contract both terms
--! are deterministic and byte-disjoint, so either one is a valid equality
--! discriminator and a single byte comparison is correct.
--!
--! ASSUMPTION (locked by a negative test in v3_jsonb_tests.rs): hm and oc byte
--! distributions never collide at a given selector. The crypto layer configures
--! a selector for eq XOR ordered, so both sides of a real comparison carry the
--! same term type; and an oc value carries a leading domain-tag byte an hm never
--! has. Unlike v2's explicit `has_hmac(both)`/`has_ore_cllw(both)`/`ELSE false`
--! CASE, this collapse would wrongly match an hm needle against an oc leaf if
--! their hex bytes were ever identical — which the contract prevents. The
--! negative-containment test guards against regression.
--!
--! @param a jsonb[] sv array to search within.
--! @param b jsonb sv element to search for.
--! @return boolean True if b is found in any element of a.
CREATE FUNCTION eql_v3.ste_vec_contains(a jsonb[], b jsonb)
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
      result := result OR (
        eql_v3.selector(_a) = eql_v3.selector(b)
        AND eql_v3.eq_term(_a::eql_v3.ste_vec_entry) = eql_v3.eq_term(b::eql_v3.ste_vec_entry)
      );
      EXIT WHEN result;
    END LOOP;

    RETURN result;
  END;
$$ LANGUAGE plpgsql;

--! @brief Does encrypted value `a` contain all sv elements of `b`?
--!
--! Empty b is always contained. Each element of b must match selector + eq_term
--! in some element of a.
--!
--! @param a eql_v3.json Container.
--! @param b eql_v3.json Elements to find.
--! @return boolean True if all elements of b are contained in a.
--! @see eql_v3.ste_vec_contains(jsonb[], jsonb)
CREATE FUNCTION eql_v3.ste_vec_contains(a eql_v3.json, b eql_v3.json)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    result boolean;
    sv_a jsonb[];
    sv_b jsonb[];
    _b jsonb;
  BEGIN
    sv_a := eql_v3.ste_vec(a);
    sv_b := eql_v3.ste_vec(b);

    IF array_length(sv_b, 1) IS NULL THEN
      RETURN true;
    END IF;

    IF array_length(sv_a, 1) IS NULL THEN
      RETURN false;
    END IF;

    result := true;

    FOR idx IN 1..array_length(sv_b, 1) LOOP
      _b := sv_b[idx];
      result := result AND eql_v3.ste_vec_contains(sv_a, _b);
    END LOOP;

    RETURN result;
  END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------------------------
-- Path queries (text selector only)
------------------------------------------------------------------------------

--! @brief Query encrypted JSONB for sv elements matching `selector`.
--!
--! Returns one ste_vec_entry row per matching encrypted element. Returns empty
--! set on no match. It deliberately does not wrap multiple matches as an
--! eql_v3.json document, because the root document domain requires an `sv`
--! array and single leaves belong to eql_v3.ste_vec_entry.
--!
--! @param val jsonb encrypted EQL payload with `sv`.
--! @param selector text Selector hash (`s` value).
--! @return SETOF eql_v3.ste_vec_entry Matching encrypted entries.
--! @see eql_v3.jsonb_path_query_first
CREATE FUNCTION eql_v3.jsonb_path_query(val jsonb, selector text)
  RETURNS SETOF eql_v3.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (eql_v3.meta_data(val) || elem)::eql_v3.ste_vec_entry
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
--! @return eql_v3.ste_vec_entry First matching element or NULL.
CREATE FUNCTION eql_v3.jsonb_path_query_first(val jsonb, selector text)
  RETURNS eql_v3.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (eql_v3.meta_data(val) || elem)::eql_v3.ste_vec_entry
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
    IF eql_v3.is_ste_vec_array(val) THEN
      sv := eql_v3.ste_vec(val);
      RETURN array_length(sv, 1);
    END IF;

    RAISE 'cannot get array length of a non-array';
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract elements of an encrypted JSONB array as rows.
--! @param val jsonb encrypted EQL payload (must have `a` flag true).
--! @return SETOF eql_v3.ste_vec_entry One row per element (metadata preserved).
--! @throws Exception 'cannot extract elements from non-array' if not an array.
CREATE FUNCTION eql_v3.jsonb_array_elements(val jsonb)
  RETURNS SETOF eql_v3.ste_vec_entry
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv jsonb[];
    meta jsonb;
    item jsonb;
  BEGIN
    IF NOT eql_v3.is_ste_vec_array(val) THEN
      RAISE 'cannot extract elements from non-array';
    END IF;

    meta := eql_v3.meta_data(val);
    sv := eql_v3.ste_vec(val);

    FOR idx IN 1..array_length(sv, 1) LOOP
      item = sv[idx];
      RETURN NEXT (meta || item)::eql_v3.ste_vec_entry;
    END LOOP;

    RETURN;
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract elements of an encrypted JSONB array as ciphertext text.
--! @param val jsonb encrypted EQL payload (must have `a` flag true).
--! @return SETOF text One ciphertext per element.
--! @throws Exception 'cannot extract elements from non-array' if not an array.
CREATE FUNCTION eql_v3.jsonb_array_elements_text(val jsonb)
  RETURNS SETOF text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv jsonb[];
  BEGIN
    IF NOT eql_v3.is_ste_vec_array(val) THEN
      RAISE 'cannot extract elements from non-array';
    END IF;

    sv := eql_v3.ste_vec(val);

    FOR idx IN 1..array_length(sv, 1) LOOP
      RETURN NEXT eql_v3.ciphertext(sv[idx]);
    END LOOP;

    RETURN;
  END;
$$ LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE
-- Source is src/v3/version.template

DROP FUNCTION IF EXISTS eql_v3.version();

--! @file v3/version.sql
--! @brief EQL version reporting (self-contained eql_v3 surface)
--!
--! This file is auto-generated from src/v3/version.template during build.
--! The DEV placeholder is replaced with the actual release
--! version (bare semver, e.g. "3.0.0") supplied via `mise run build --version`,
--! or "DEV" for development builds.

--! @brief Get the installed EQL version string
--!
--! Returns the version string for the installed EQL library. This value is
--! baked in at build time from the release tag.
--!
--! @return text Version string (e.g. "3.0.0" or "DEV" for development builds)
--!
--! @note Auto-generated during build from src/v3/version.template
--!
--! @example
--! -- Check installed EQL version
--! SELECT eql_v3.version();
--! -- Returns: '3.0.0'
CREATE FUNCTION eql_v3.version()
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT 'DEV';
$$ LANGUAGE SQL;

--! @brief Schema-level version marker for obj_description() discoverability
--!
--! Mirrors eql_v3.version() as a comment on the schema so the installed
--! version can also be read via obj_description('eql_v3'::regnamespace).
COMMENT ON SCHEMA eql_v3 IS 'DEV';
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_ord_aggregates.sql
--! @brief Aggregates for eql_v3.int4_ord.

--! @brief State function for min on eql_v3.int4_ord.
--! @param state eql_v3.int4_ord
--! @param value eql_v3.int4_ord
--! @return eql_v3.int4_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.int4_ord, value eql_v3.int4_ord)
RETURNS eql_v3.int4_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.int4_ord.
--! @param input eql_v3.int4_ord
--! @return eql_v3.int4_ord
CREATE AGGREGATE eql_v3.min(eql_v3.int4_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.int4_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.int4_ord.
--! @param state eql_v3.int4_ord
--! @param value eql_v3.int4_ord
--! @return eql_v3.int4_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.int4_ord, value eql_v3.int4_ord)
RETURNS eql_v3.int4_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.int4_ord.
--! @param input eql_v3.int4_ord
--! @return eql_v3.int4_ord
CREATE AGGREGATE eql_v3.max(eql_v3.int4_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.int4_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_functions.sql
--! @brief Functions for eql_v3.int4.

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param selector text
--! @return eql_v3.int4
CREATE FUNCTION eql_v3."->"(a eql_v3.int4, selector text)
RETURNS eql_v3.int4 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param selector integer
--! @return eql_v3.int4
CREATE FUNCTION eql_v3."->"(a eql_v3.int4, selector integer)
RETURNS eql_v3.int4 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param selector eql_v3.int4
--! @return eql_v3.int4
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int4)
RETURNS eql_v3.int4 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param selector eql_v3.int4
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int4)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int4, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int4, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int4, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int4, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int4, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int4, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int4, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int4, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b eql_v3.int4
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4, b eql_v3.int4)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a eql_v3.int4
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4.
--! @param a jsonb
--! @param b eql_v3.int4
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int4)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_eq_operators.sql
--! @brief Operators for eql_v3.int4_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = eql_v3.int4_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_ord_ore_functions.sql
--! @brief Functions for eql_v3.int4_ord_ore.

--! @brief Index extractor for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int4_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.int4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.int4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.int4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.int4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.int4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.int4_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int4_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int4_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int4_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param selector text
--! @return eql_v3.int4_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.int4_ord_ore, selector text)
RETURNS eql_v3.int4_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param selector integer
--! @return eql_v3.int4_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.int4_ord_ore, selector integer)
RETURNS eql_v3.int4_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.int4_ord_ore
--! @return eql_v3.int4_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int4_ord_ore)
RETURNS eql_v3.int4_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int4_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.int4_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int4_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int4_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int4_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int4_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int4_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int4_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int4_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int4_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int4_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int4_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b eql_v3.int4_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4_ord_ore, b eql_v3.int4_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a eql_v3.int4_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int4_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int4_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int4_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int4_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int4_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_ord_ore_operators.sql
--! @brief Operators for eql_v3.int4_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = eql_v3.int4_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_operators.sql
--! @brief Operators for eql_v3.int4.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int4, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int4, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int4, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int4, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int4, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int4, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int4, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int4, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int4, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int4, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int4, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4, RIGHTARG = eql_v3.int4
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int4, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int4
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int4/int4_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.int4_ord_ore.

--! @brief State function for min on eql_v3.int4_ord_ore.
--! @param state eql_v3.int4_ord_ore
--! @param value eql_v3.int4_ord_ore
--! @return eql_v3.int4_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.int4_ord_ore, value eql_v3.int4_ord_ore)
RETURNS eql_v3.int4_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.int4_ord_ore.
--! @param input eql_v3.int4_ord_ore
--! @return eql_v3.int4_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.int4_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.int4_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.int4_ord_ore.
--! @param state eql_v3.int4_ord_ore
--! @param value eql_v3.int4_ord_ore
--! @return eql_v3.int4_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.int4_ord_ore, value eql_v3.int4_ord_ore)
RETURNS eql_v3.int4_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.int4_ord_ore.
--! @param input eql_v3.int4_ord_ore
--! @return eql_v3.int4_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.int4_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.int4_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.timestamptz_ord_ore.

--! @brief State function for min on eql_v3.timestamptz_ord_ore.
--! @param state eql_v3.timestamptz_ord_ore
--! @param value eql_v3.timestamptz_ord_ore
--! @return eql_v3.timestamptz_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.timestamptz_ord_ore, value eql_v3.timestamptz_ord_ore)
RETURNS eql_v3.timestamptz_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.timestamptz_ord_ore.
--! @param input eql_v3.timestamptz_ord_ore
--! @return eql_v3.timestamptz_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.timestamptz_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.timestamptz_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.timestamptz_ord_ore.
--! @param state eql_v3.timestamptz_ord_ore
--! @param value eql_v3.timestamptz_ord_ore
--! @return eql_v3.timestamptz_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.timestamptz_ord_ore, value eql_v3.timestamptz_ord_ore)
RETURNS eql_v3.timestamptz_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.timestamptz_ord_ore.
--! @param input eql_v3.timestamptz_ord_ore
--! @return eql_v3.timestamptz_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.timestamptz_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.timestamptz_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_functions.sql
--! @brief Functions for eql_v3.timestamptz.

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.timestamptz, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.timestamptz)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param selector text
--! @return eql_v3.timestamptz
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz, selector text)
RETURNS eql_v3.timestamptz IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param selector integer
--! @return eql_v3.timestamptz
CREATE FUNCTION eql_v3."->"(a eql_v3.timestamptz, selector integer)
RETURNS eql_v3.timestamptz IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param selector eql_v3.timestamptz
--! @return eql_v3.timestamptz
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.timestamptz)
RETURNS eql_v3.timestamptz IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.timestamptz, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param selector eql_v3.timestamptz
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.timestamptz)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.timestamptz, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.timestamptz, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.timestamptz, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.timestamptz, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.timestamptz, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.timestamptz, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.timestamptz, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.timestamptz, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.timestamptz, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b eql_v3.timestamptz
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz, b eql_v3.timestamptz)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a eql_v3.timestamptz
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.timestamptz, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.timestamptz.
--! @param a jsonb
--! @param b eql_v3.timestamptz
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.timestamptz)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.timestamptz'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_eq_operators.sql
--! @brief Operators for eql_v3.timestamptz_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = eql_v3.timestamptz_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_ord_aggregates.sql
--! @brief Aggregates for eql_v3.timestamptz_ord.

--! @brief State function for min on eql_v3.timestamptz_ord.
--! @param state eql_v3.timestamptz_ord
--! @param value eql_v3.timestamptz_ord
--! @return eql_v3.timestamptz_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.timestamptz_ord, value eql_v3.timestamptz_ord)
RETURNS eql_v3.timestamptz_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.timestamptz_ord.
--! @param input eql_v3.timestamptz_ord
--! @return eql_v3.timestamptz_ord
CREATE AGGREGATE eql_v3.min(eql_v3.timestamptz_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.timestamptz_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.timestamptz_ord.
--! @param state eql_v3.timestamptz_ord
--! @param value eql_v3.timestamptz_ord
--! @return eql_v3.timestamptz_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.timestamptz_ord, value eql_v3.timestamptz_ord)
RETURNS eql_v3.timestamptz_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.timestamptz_ord.
--! @param input eql_v3.timestamptz_ord
--! @return eql_v3.timestamptz_ord
CREATE AGGREGATE eql_v3.max(eql_v3.timestamptz_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.timestamptz_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/timestamptz/timestamptz_operators.sql
--! @brief Operators for eql_v3.timestamptz.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = eql_v3.timestamptz
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.timestamptz, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.timestamptz
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_eq_functions.sql
--! @brief Functions for eql_v3.int2_eq.

--! @brief Index extractor for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.int2_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int2_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.int2_eq) $$;

--! @brief Operator wrapper for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int2_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.int2_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int2_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.int2_eq) $$;

--! @brief Operator wrapper for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int2_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.int2_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int2_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int2_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int2_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int2_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int2_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int2_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int2_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param selector text
--! @return eql_v3.int2_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.int2_eq, selector text)
RETURNS eql_v3.int2_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param selector integer
--! @return eql_v3.int2_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.int2_eq, selector integer)
RETURNS eql_v3.int2_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param selector eql_v3.int2_eq
--! @return eql_v3.int2_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int2_eq)
RETURNS eql_v3.int2_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int2_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param selector eql_v3.int2_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int2_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int2_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int2_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int2_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int2_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int2_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int2_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int2_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int2_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int2_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b eql_v3.int2_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2_eq, b eql_v3.int2_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a eql_v3.int2_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int2_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int2_eq.
--! @param a jsonb
--! @param b eql_v3.int2_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int2_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int2_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_ord_aggregates.sql
--! @brief Aggregates for eql_v3.int2_ord.

--! @brief State function for min on eql_v3.int2_ord.
--! @param state eql_v3.int2_ord
--! @param value eql_v3.int2_ord
--! @return eql_v3.int2_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.int2_ord, value eql_v3.int2_ord)
RETURNS eql_v3.int2_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.int2_ord.
--! @param input eql_v3.int2_ord
--! @return eql_v3.int2_ord
CREATE AGGREGATE eql_v3.min(eql_v3.int2_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.int2_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.int2_ord.
--! @param state eql_v3.int2_ord
--! @param value eql_v3.int2_ord
--! @return eql_v3.int2_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.int2_ord, value eql_v3.int2_ord)
RETURNS eql_v3.int2_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.int2_ord.
--! @param input eql_v3.int2_ord
--! @return eql_v3.int2_ord
CREATE AGGREGATE eql_v3.max(eql_v3.int2_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.int2_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_operators.sql
--! @brief Operators for eql_v3.int2.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int2, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int2, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int2, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int2, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int2, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int2, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int2, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int2, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2, RIGHTARG = eql_v3.int2
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_eq_operators.sql
--! @brief Operators for eql_v3.int2_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = eql_v3.int2_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int2_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int2_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int2/int2_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.int2_ord_ore.

--! @brief State function for min on eql_v3.int2_ord_ore.
--! @param state eql_v3.int2_ord_ore
--! @param value eql_v3.int2_ord_ore
--! @return eql_v3.int2_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.int2_ord_ore, value eql_v3.int2_ord_ore)
RETURNS eql_v3.int2_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.int2_ord_ore.
--! @param input eql_v3.int2_ord_ore
--! @return eql_v3.int2_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.int2_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.int2_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.int2_ord_ore.
--! @param state eql_v3.int2_ord_ore
--! @param value eql_v3.int2_ord_ore
--! @return eql_v3.int2_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.int2_ord_ore, value eql_v3.int2_ord_ore)
RETURNS eql_v3.int2_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.int2_ord_ore.
--! @param input eql_v3.int2_ord_ore
--! @return eql_v3.int2_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.int2_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.int2_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.float8_ord_ore.

--! @brief State function for min on eql_v3.float8_ord_ore.
--! @param state eql_v3.float8_ord_ore
--! @param value eql_v3.float8_ord_ore
--! @return eql_v3.float8_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.float8_ord_ore, value eql_v3.float8_ord_ore)
RETURNS eql_v3.float8_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.float8_ord_ore.
--! @param input eql_v3.float8_ord_ore
--! @return eql_v3.float8_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.float8_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.float8_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.float8_ord_ore.
--! @param state eql_v3.float8_ord_ore
--! @param value eql_v3.float8_ord_ore
--! @return eql_v3.float8_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.float8_ord_ore, value eql_v3.float8_ord_ore)
RETURNS eql_v3.float8_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.float8_ord_ore.
--! @param input eql_v3.float8_ord_ore
--! @return eql_v3.float8_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.float8_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.float8_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_eq_functions.sql
--! @brief Functions for eql_v3.float8_eq.

--! @brief Index extractor for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.float8_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float8_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.float8_eq) $$;

--! @brief Operator wrapper for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.float8_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float8_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.float8_eq) $$;

--! @brief Operator wrapper for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.float8_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param selector text
--! @return eql_v3.float8_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.float8_eq, selector text)
RETURNS eql_v3.float8_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param selector integer
--! @return eql_v3.float8_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.float8_eq, selector integer)
RETURNS eql_v3.float8_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param selector eql_v3.float8_eq
--! @return eql_v3.float8_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float8_eq)
RETURNS eql_v3.float8_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float8_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param selector eql_v3.float8_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float8_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float8_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float8_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float8_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float8_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float8_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float8_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float8_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float8_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float8_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b eql_v3.float8_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8_eq, b eql_v3.float8_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a eql_v3.float8_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float8_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float8_eq.
--! @param a jsonb
--! @param b eql_v3.float8_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float8_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float8_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_ord_operators.sql
--! @brief Operators for eql_v3.float8_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = eql_v3.float8_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_ord_aggregates.sql
--! @brief Aggregates for eql_v3.float8_ord.

--! @brief State function for min on eql_v3.float8_ord.
--! @param state eql_v3.float8_ord
--! @param value eql_v3.float8_ord
--! @return eql_v3.float8_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.float8_ord, value eql_v3.float8_ord)
RETURNS eql_v3.float8_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.float8_ord.
--! @param input eql_v3.float8_ord
--! @return eql_v3.float8_ord
CREATE AGGREGATE eql_v3.min(eql_v3.float8_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.float8_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.float8_ord.
--! @param state eql_v3.float8_ord
--! @param value eql_v3.float8_ord
--! @return eql_v3.float8_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.float8_ord, value eql_v3.float8_ord)
RETURNS eql_v3.float8_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.float8_ord.
--! @param input eql_v3.float8_ord
--! @return eql_v3.float8_ord
CREATE AGGREGATE eql_v3.max(eql_v3.float8_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.float8_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_operators.sql
--! @brief Operators for eql_v3.float8.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float8, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float8, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float8, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float8, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float8, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float8, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float8, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float8, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8, RIGHTARG = eql_v3.float8
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float8/float8_eq_operators.sql
--! @brief Operators for eql_v3.float8_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = eql_v3.float8_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float8_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_ord_functions.sql
--! @brief Functions for eql_v3.date_ord.

--! @brief Index extractor for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.date_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.date_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.date_ord) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.date_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.date_ord) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.date_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.date_ord) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.date_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.date_ord) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.date_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.date_ord) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.date_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.date_ord) $$;

--! @brief Operator wrapper for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.date_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.date_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.date_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.date_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.date_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param selector text
--! @return eql_v3.date_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.date_ord, selector text)
RETURNS eql_v3.date_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param selector integer
--! @return eql_v3.date_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.date_ord, selector integer)
RETURNS eql_v3.date_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a jsonb
--! @param selector eql_v3.date_ord
--! @return eql_v3.date_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.date_ord)
RETURNS eql_v3.date_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.date_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a jsonb
--! @param selector eql_v3.date_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.date_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.date_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.date_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.date_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.date_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.date_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.date_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.date_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.date_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.date_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b eql_v3.date_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date_ord, b eql_v3.date_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.date_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.date_ord.
--! @param a jsonb
--! @param b eql_v3.date_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.date_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.date_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_eq_operators.sql
--! @brief Operators for eql_v3.date_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.date_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date_eq, RIGHTARG = eql_v3.date_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_operators.sql
--! @brief Operators for eql_v3.date.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.date, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.date, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.date, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.date, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.date, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.date, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.date, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.date, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date, RIGHTARG = eql_v3.date
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.date_ord_ore.

--! @brief State function for min on eql_v3.date_ord_ore.
--! @param state eql_v3.date_ord_ore
--! @param value eql_v3.date_ord_ore
--! @return eql_v3.date_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.date_ord_ore, value eql_v3.date_ord_ore)
RETURNS eql_v3.date_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.date_ord_ore.
--! @param input eql_v3.date_ord_ore
--! @return eql_v3.date_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.date_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.date_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.date_ord_ore.
--! @param state eql_v3.date_ord_ore
--! @param value eql_v3.date_ord_ore
--! @return eql_v3.date_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.date_ord_ore, value eql_v3.date_ord_ore)
RETURNS eql_v3.date_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.date_ord_ore.
--! @param input eql_v3.date_ord_ore
--! @return eql_v3.date_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.date_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.date_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_ord_operators.sql
--! @brief Operators for eql_v3.date_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.date_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.date_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.date_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date_ord, RIGHTARG = eql_v3.date_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.date_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.date_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/date/date_ord_aggregates.sql
--! @brief Aggregates for eql_v3.date_ord.

--! @brief State function for min on eql_v3.date_ord.
--! @param state eql_v3.date_ord
--! @param value eql_v3.date_ord
--! @return eql_v3.date_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.date_ord, value eql_v3.date_ord)
RETURNS eql_v3.date_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.date_ord.
--! @param input eql_v3.date_ord
--! @return eql_v3.date_ord
CREATE AGGREGATE eql_v3.min(eql_v3.date_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.date_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.date_ord.
--! @param state eql_v3.date_ord
--! @param value eql_v3.date_ord
--! @return eql_v3.date_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.date_ord, value eql_v3.date_ord)
RETURNS eql_v3.date_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.date_ord.
--! @param input eql_v3.date_ord
--! @return eql_v3.date_ord
CREATE AGGREGATE eql_v3.max(eql_v3.date_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.date_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_ord_functions.sql
--! @brief Functions for eql_v3.numeric_ord.

--! @brief Index extractor for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.numeric_ord)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.numeric_ord) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.numeric_ord) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.numeric_ord) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.numeric_ord) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.numeric_ord) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.numeric_ord) $$;

--! @brief Operator wrapper for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.numeric_ord) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric_ord, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.numeric_ord)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param selector text
--! @return eql_v3.numeric_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric_ord, selector text)
RETURNS eql_v3.numeric_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param selector integer
--! @return eql_v3.numeric_ord
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric_ord, selector integer)
RETURNS eql_v3.numeric_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a jsonb
--! @param selector eql_v3.numeric_ord
--! @return eql_v3.numeric_ord
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.numeric_ord)
RETURNS eql_v3.numeric_ord IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric_ord, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric_ord, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a jsonb
--! @param selector eql_v3.numeric_ord
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.numeric_ord)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.numeric_ord, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.numeric_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.numeric_ord, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.numeric_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.numeric_ord, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.numeric_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.numeric_ord, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_ord, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_ord, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.numeric_ord, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b eql_v3.numeric_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric_ord, b eql_v3.numeric_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a eql_v3.numeric_ord
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric_ord, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric_ord.
--! @param a jsonb
--! @param b eql_v3.numeric_ord
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.numeric_ord)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric_ord'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_functions.sql
--! @brief Functions for eql_v3.numeric.

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.numeric, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.numeric)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param selector text
--! @return eql_v3.numeric
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric, selector text)
RETURNS eql_v3.numeric IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param selector integer
--! @return eql_v3.numeric
CREATE FUNCTION eql_v3."->"(a eql_v3.numeric, selector integer)
RETURNS eql_v3.numeric IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param selector eql_v3.numeric
--! @return eql_v3.numeric
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.numeric)
RETURNS eql_v3.numeric IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.numeric, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param selector eql_v3.numeric
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.numeric)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.numeric, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.numeric, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.numeric, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.numeric, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.numeric, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.numeric, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.numeric, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.numeric, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.numeric, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b eql_v3.numeric
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric, b eql_v3.numeric)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a eql_v3.numeric
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.numeric, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.numeric.
--! @param a jsonb
--! @param b eql_v3.numeric
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.numeric)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.numeric'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_eq_operators.sql
--! @brief Operators for eql_v3.numeric_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = eql_v3.numeric_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.numeric_ord_ore.

--! @brief State function for min on eql_v3.numeric_ord_ore.
--! @param state eql_v3.numeric_ord_ore
--! @param value eql_v3.numeric_ord_ore
--! @return eql_v3.numeric_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.numeric_ord_ore, value eql_v3.numeric_ord_ore)
RETURNS eql_v3.numeric_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.numeric_ord_ore.
--! @param input eql_v3.numeric_ord_ore
--! @return eql_v3.numeric_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.numeric_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.numeric_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.numeric_ord_ore.
--! @param state eql_v3.numeric_ord_ore
--! @param value eql_v3.numeric_ord_ore
--! @return eql_v3.numeric_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.numeric_ord_ore, value eql_v3.numeric_ord_ore)
RETURNS eql_v3.numeric_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.numeric_ord_ore.
--! @param input eql_v3.numeric_ord_ore
--! @return eql_v3.numeric_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.numeric_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.numeric_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_operators.sql
--! @brief Operators for eql_v3.numeric.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.numeric, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.numeric, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.numeric, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.numeric, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.numeric, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.numeric, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric, RIGHTARG = eql_v3.numeric
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_ord_operators.sql
--! @brief Operators for eql_v3.numeric_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = eql_v3.numeric_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.numeric_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.numeric_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/numeric/numeric_ord_aggregates.sql
--! @brief Aggregates for eql_v3.numeric_ord.

--! @brief State function for min on eql_v3.numeric_ord.
--! @param state eql_v3.numeric_ord
--! @param value eql_v3.numeric_ord
--! @return eql_v3.numeric_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.numeric_ord, value eql_v3.numeric_ord)
RETURNS eql_v3.numeric_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.numeric_ord.
--! @param input eql_v3.numeric_ord
--! @return eql_v3.numeric_ord
CREATE AGGREGATE eql_v3.min(eql_v3.numeric_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.numeric_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.numeric_ord.
--! @param state eql_v3.numeric_ord
--! @param value eql_v3.numeric_ord
--! @return eql_v3.numeric_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.numeric_ord, value eql_v3.numeric_ord)
RETURNS eql_v3.numeric_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.numeric_ord.
--! @param input eql_v3.numeric_ord
--! @return eql_v3.numeric_ord
CREATE AGGREGATE eql_v3.max(eql_v3.numeric_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.numeric_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/bool/bool_operators.sql
--! @brief Operators for eql_v3.bool.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.bool, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.bool, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.bool, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.bool, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.bool, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.bool, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.bool, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.bool, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.bool, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.bool, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.bool, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.bool, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.bool, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.bool, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.bool, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.bool, RIGHTARG = eql_v3.bool
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.bool, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.bool
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_operators.sql
--! @brief Operators for eql_v3.int8.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int8, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int8, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int8, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int8, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int8, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int8, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int8, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int8, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8, RIGHTARG = eql_v3.int8
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_eq_functions.sql
--! @brief Functions for eql_v3.int8_eq.

--! @brief Index extractor for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @return eql_v3.hmac_256
CREATE FUNCTION eql_v3.eq_term(a eql_v3.int8_eq)
RETURNS eql_v3.hmac_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.hmac_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b::eql_v3.int8_eq) $$;

--! @brief Operator wrapper for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.int8_eq) = eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8_eq, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b::eql_v3.int8_eq) $$;

--! @brief Operator wrapper for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int8_eq)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.eq_term(a::eql_v3.int8_eq) <> eql_v3.eq_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8_eq, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int8_eq)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param selector text
--! @return eql_v3.int8_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.int8_eq, selector text)
RETURNS eql_v3.int8_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param selector integer
--! @return eql_v3.int8_eq
CREATE FUNCTION eql_v3."->"(a eql_v3.int8_eq, selector integer)
RETURNS eql_v3.int8_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param selector eql_v3.int8_eq
--! @return eql_v3.int8_eq
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int8_eq)
RETURNS eql_v3.int8_eq IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8_eq, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8_eq, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param selector eql_v3.int8_eq
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int8_eq)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int8_eq, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int8_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int8_eq, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int8_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int8_eq, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int8_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int8_eq, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_eq, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_eq, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int8_eq, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b eql_v3.int8_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8_eq, b eql_v3.int8_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a eql_v3.int8_eq
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8_eq, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_eq.
--! @param a jsonb
--! @param b eql_v3.int8_eq
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int8_eq)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_eq'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_ord_ore_functions.sql
--! @brief Functions for eql_v3.int8_ord_ore.

--! @brief Index extractor for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @return eql_v3.ore_block_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int8_ord_ore)
RETURNS eql_v3.ore_block_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.int8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.int8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord_ore) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b::eql_v3.int8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord_ore) < eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <= eql_v3.ord_term(b::eql_v3.int8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord_ore) <= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) > eql_v3.ord_term(b::eql_v3.int8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord_ore) > eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) >= eql_v3.ord_term(b::eql_v3.int8_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.int8_ord_ore) >= eql_v3.ord_term(b) $$;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.int8_ord_ore, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.int8_ord_ore)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param selector text
--! @return eql_v3.int8_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.int8_ord_ore, selector text)
RETURNS eql_v3.int8_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param selector integer
--! @return eql_v3.int8_ord_ore
CREATE FUNCTION eql_v3."->"(a eql_v3.int8_ord_ore, selector integer)
RETURNS eql_v3.int8_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.int8_ord_ore
--! @return eql_v3.int8_ord_ore
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.int8_ord_ore)
RETURNS eql_v3.int8_ord_ore IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8_ord_ore, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.int8_ord_ore, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param selector eql_v3.int8_ord_ore
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.int8_ord_ore)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.int8_ord_ore, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.int8_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.int8_ord_ore, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.int8_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.int8_ord_ore, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.int8_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.int8_ord_ore, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_ord_ore, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_ord_ore, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.int8_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.int8_ord_ore, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b eql_v3.int8_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8_ord_ore, b eql_v3.int8_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a eql_v3.int8_ord_ore
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.int8_ord_ore, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.int8_ord_ore.
--! @param a jsonb
--! @param b eql_v3.int8_ord_ore
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.int8_ord_ore)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.int8_ord_ore'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_ord_operators.sql
--! @brief Operators for eql_v3.int8_ord.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = eql_v3.int8_ord
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8_ord, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_ord_ore_operators.sql
--! @brief Operators for eql_v3.int8_ord_ore.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = eql_v3.int8_ord_ore
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8_ord_ore, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_ord_ore
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.int8_ord_ore.

--! @brief State function for min on eql_v3.int8_ord_ore.
--! @param state eql_v3.int8_ord_ore
--! @param value eql_v3.int8_ord_ore
--! @return eql_v3.int8_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.int8_ord_ore, value eql_v3.int8_ord_ore)
RETURNS eql_v3.int8_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.int8_ord_ore.
--! @param input eql_v3.int8_ord_ore
--! @return eql_v3.int8_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.int8_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.int8_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.int8_ord_ore.
--! @param state eql_v3.int8_ord_ore
--! @param value eql_v3.int8_ord_ore
--! @return eql_v3.int8_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.int8_ord_ore, value eql_v3.int8_ord_ore)
RETURNS eql_v3.int8_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.int8_ord_ore.
--! @param input eql_v3.int8_ord_ore
--! @return eql_v3.int8_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.int8_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.int8_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_ord_aggregates.sql
--! @brief Aggregates for eql_v3.int8_ord.

--! @brief State function for min on eql_v3.int8_ord.
--! @param state eql_v3.int8_ord
--! @param value eql_v3.int8_ord
--! @return eql_v3.int8_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.int8_ord, value eql_v3.int8_ord)
RETURNS eql_v3.int8_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.int8_ord.
--! @param input eql_v3.int8_ord
--! @return eql_v3.int8_ord
CREATE AGGREGATE eql_v3.min(eql_v3.int8_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.int8_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.int8_ord.
--! @param state eql_v3.int8_ord
--! @param value eql_v3.int8_ord
--! @return eql_v3.int8_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.int8_ord, value eql_v3.int8_ord)
RETURNS eql_v3.int8_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.int8_ord.
--! @param input eql_v3.int8_ord
--! @return eql_v3.int8_ord
CREATE AGGREGATE eql_v3.max(eql_v3.int8_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.int8_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/int8/int8_eq_operators.sql
--! @brief Operators for eql_v3.int8_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = eql_v3.int8_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.int8_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.int8_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_functions.sql
--! @brief Functions for eql_v3.text.

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.text, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param selector text
--! @return eql_v3.text
CREATE FUNCTION eql_v3."->"(a eql_v3.text, selector text)
RETURNS eql_v3.text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param selector integer
--! @return eql_v3.text
CREATE FUNCTION eql_v3."->"(a eql_v3.text, selector integer)
RETURNS eql_v3.text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param selector eql_v3.text
--! @return eql_v3.text
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.text)
RETURNS eql_v3.text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.text, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param selector eql_v3.text
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.text, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.text, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.text, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.text, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.text, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.text, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.text, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.text, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.text, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b eql_v3.text
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text, b eql_v3.text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a eql_v3.text
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.text, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.text.
--! @param a jsonb
--! @param b eql_v3.text
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.text'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_match_operators.sql
--! @brief Operators for eql_v3.text_match.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match,
  COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb,
  COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match,
  COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match,
  COMMUTATOR = @>, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb,
  COMMUTATOR = @>, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match,
  COMMUTATOR = @>, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_match, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_match, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_match, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_match, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.text_match, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.text_match, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.text_match, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.text_match, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.text_match, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_match, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_match, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_match, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.text_match, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_match, RIGHTARG = eql_v3.text_match
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_match, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_match
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_search_operators.sql
--! @brief Operators for eql_v3.text_search.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = >=, NEGATOR = >, RESTRICT = scalarlesel, JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <, NEGATOR = <=, RESTRICT = scalargtsel, JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <=, NEGATOR = <, RESTRICT = scalargesel, JOIN = scalargejoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = @>, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb,
  COMMUTATOR = @>, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search,
  COMMUTATOR = @>, RESTRICT = contsel, JOIN = contjoinsel
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_search, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_search, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_search, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_search, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.text_search, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.text_search, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.text_search, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.text_search, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.text_search, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_search, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_search, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_search, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.text_search, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_search, RIGHTARG = eql_v3.text_search
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_search, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_search
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_eq_operators.sql
--! @brief Operators for eql_v3.text_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.text_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_eq, RIGHTARG = eql_v3.text_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.text_ord_ore.

--! @brief State function for min on eql_v3.text_ord_ore.
--! @param state eql_v3.text_ord_ore
--! @param value eql_v3.text_ord_ore
--! @return eql_v3.text_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.text_ord_ore, value eql_v3.text_ord_ore)
RETURNS eql_v3.text_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.text_ord_ore.
--! @param input eql_v3.text_ord_ore
--! @return eql_v3.text_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.text_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.text_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.text_ord_ore.
--! @param state eql_v3.text_ord_ore
--! @param value eql_v3.text_ord_ore
--! @return eql_v3.text_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.text_ord_ore, value eql_v3.text_ord_ore)
RETURNS eql_v3.text_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.text_ord_ore.
--! @param input eql_v3.text_ord_ore
--! @return eql_v3.text_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.text_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.text_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_ord_aggregates.sql
--! @brief Aggregates for eql_v3.text_ord.

--! @brief State function for min on eql_v3.text_ord.
--! @param state eql_v3.text_ord
--! @param value eql_v3.text_ord
--! @return eql_v3.text_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.text_ord, value eql_v3.text_ord)
RETURNS eql_v3.text_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.text_ord.
--! @param input eql_v3.text_ord
--! @return eql_v3.text_ord
CREATE AGGREGATE eql_v3.min(eql_v3.text_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.text_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.text_ord.
--! @param state eql_v3.text_ord
--! @param value eql_v3.text_ord
--! @return eql_v3.text_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.text_ord, value eql_v3.text_ord)
RETURNS eql_v3.text_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.text_ord.
--! @param input eql_v3.text_ord
--! @return eql_v3.text_ord
CREATE AGGREGATE eql_v3.max(eql_v3.text_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.text_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_operators.sql
--! @brief Operators for eql_v3.text.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.text, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.text, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.text, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.text, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.text, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.text, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.text, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.text, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.text, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.text, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.text, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text, RIGHTARG = eql_v3.text
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.text, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.text
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/text/text_search_aggregates.sql
--! @brief Aggregates for eql_v3.text_search.

--! @brief State function for min on eql_v3.text_search.
--! @param state eql_v3.text_search
--! @param value eql_v3.text_search
--! @return eql_v3.text_search
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.text_search, value eql_v3.text_search)
RETURNS eql_v3.text_search
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.text_search.
--! @param input eql_v3.text_search
--! @return eql_v3.text_search
CREATE AGGREGATE eql_v3.min(eql_v3.text_search) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.text_search,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.text_search.
--! @param state eql_v3.text_search
--! @param value eql_v3.text_search
--! @return eql_v3.text_search
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.text_search, value eql_v3.text_search)
RETURNS eql_v3.text_search
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.text_search.
--! @param input eql_v3.text_search
--! @return eql_v3.text_search
CREATE AGGREGATE eql_v3.max(eql_v3.text_search) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.text_search,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_eq_operators.sql
--! @brief Operators for eql_v3.float4_eq.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq,
  COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq,
  COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = eql_v3.float4_eq
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4_eq, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4_eq
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_ord_ore_aggregates.sql
--! @brief Aggregates for eql_v3.float4_ord_ore.

--! @brief State function for min on eql_v3.float4_ord_ore.
--! @param state eql_v3.float4_ord_ore
--! @param value eql_v3.float4_ord_ore
--! @return eql_v3.float4_ord_ore
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.float4_ord_ore, value eql_v3.float4_ord_ore)
RETURNS eql_v3.float4_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.float4_ord_ore.
--! @param input eql_v3.float4_ord_ore
--! @return eql_v3.float4_ord_ore
CREATE AGGREGATE eql_v3.min(eql_v3.float4_ord_ore) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.float4_ord_ore,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.float4_ord_ore.
--! @param state eql_v3.float4_ord_ore
--! @param value eql_v3.float4_ord_ore
--! @return eql_v3.float4_ord_ore
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.float4_ord_ore, value eql_v3.float4_ord_ore)
RETURNS eql_v3.float4_ord_ore
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.float4_ord_ore.
--! @param input eql_v3.float4_ord_ore
--! @return eql_v3.float4_ord_ore
CREATE AGGREGATE eql_v3.max(eql_v3.float4_ord_ore) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.float4_ord_ore,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_functions.sql
--! @brief Functions for eql_v3.float4.

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lt(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.lt(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.lte(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.lte(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gt(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.gt(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.gte(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.gte(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '>=', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contains(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.contains(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a eql_v3.float4, b jsonb)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return boolean
CREATE FUNCTION eql_v3.contained_by(a jsonb, b eql_v3.float4)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '<@', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param selector text
--! @return eql_v3.float4
CREATE FUNCTION eql_v3."->"(a eql_v3.float4, selector text)
RETURNS eql_v3.float4 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param selector integer
--! @return eql_v3.float4
CREATE FUNCTION eql_v3."->"(a eql_v3.float4, selector integer)
RETURNS eql_v3.float4 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param selector eql_v3.float4
--! @return eql_v3.float4
CREATE FUNCTION eql_v3."->"(a jsonb, selector eql_v3.float4)
RETURNS eql_v3.float4 IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param selector text
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4, selector text)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param selector integer
--! @return text
CREATE FUNCTION eql_v3."->>"(a eql_v3.float4, selector integer)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param selector eql_v3.float4
--! @return text
CREATE FUNCTION eql_v3."->>"(a jsonb, selector eql_v3.float4)
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '->>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text
--! @return boolean
CREATE FUNCTION eql_v3."?"(a eql_v3.float4, b text)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?|"(a eql_v3.float4, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?|', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text[]
--! @return boolean
CREATE FUNCTION eql_v3."?&"(a eql_v3.float4, b text[])
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '?&', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@?"(a eql_v3.float4, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@?', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonpath
--! @return boolean
CREATE FUNCTION eql_v3."@@"(a eql_v3.float4, b jsonpath)
RETURNS boolean IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '@@', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#>"(a eql_v3.float4, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text[]
--! @return text
CREATE FUNCTION eql_v3."#>>"(a eql_v3.float4, b text[])
RETURNS text IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#>>', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4, b text)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b integer
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4, b integer)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."-"(a eql_v3.float4, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '-', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b text[]
--! @return jsonb
CREATE FUNCTION eql_v3."#-"(a eql_v3.float4, b text[])
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '#-', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b eql_v3.float4
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4, b eql_v3.float4)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a eql_v3.float4
--! @param b jsonb
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a eql_v3.float4, b jsonb)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;

--! @brief Unsupported operator blocker for eql_v3.float4.
--! @param a jsonb
--! @param b eql_v3.float4
--! @return jsonb
CREATE FUNCTION eql_v3."||"(a jsonb, b eql_v3.float4)
RETURNS jsonb IMMUTABLE PARALLEL SAFE
AS $$ BEGIN RAISE EXCEPTION 'operator % is not supported for %', '||', 'eql_v3.float4'; END; $$
LANGUAGE plpgsql;
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_ord_aggregates.sql
--! @brief Aggregates for eql_v3.float4_ord.

--! @brief State function for min on eql_v3.float4_ord.
--! @param state eql_v3.float4_ord
--! @param value eql_v3.float4_ord
--! @return eql_v3.float4_ord
CREATE FUNCTION eql_v3.min_sfunc(state eql_v3.float4_ord, value eql_v3.float4_ord)
RETURNS eql_v3.float4_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value < state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate for eql_v3.float4_ord.
--! @param input eql_v3.float4_ord
--! @return eql_v3.float4_ord
CREATE AGGREGATE eql_v3.min(eql_v3.float4_ord) (
  sfunc = eql_v3.min_sfunc,
  stype = eql_v3.float4_ord,
  combinefunc = eql_v3.min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.float4_ord.
--! @param state eql_v3.float4_ord
--! @param value eql_v3.float4_ord
--! @return eql_v3.float4_ord
CREATE FUNCTION eql_v3.max_sfunc(state eql_v3.float4_ord, value eql_v3.float4_ord)
RETURNS eql_v3.float4_ord
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF value > state THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate for eql_v3.float4_ord.
--! @param input eql_v3.float4_ord
--! @return eql_v3.float4_ord
CREATE AGGREGATE eql_v3.max(eql_v3.float4_ord) (
  sfunc = eql_v3.max_sfunc,
  stype = eql_v3.float4_ord,
  combinefunc = eql_v3.max_sfunc,
  parallel = safe
);
-- AUTOMATICALLY GENERATED FILE.

--! @file encrypted_domain/float4/float4_operators.sql
--! @brief Operators for eql_v3.float4.

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.contains,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.contained_by,
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4, RIGHTARG = text
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = eql_v3.float4, RIGHTARG = integer
);

CREATE OPERATOR -> (
  FUNCTION = eql_v3."->",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4, RIGHTARG = text
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = eql_v3.float4, RIGHTARG = integer
);

CREATE OPERATOR ->> (
  FUNCTION = eql_v3."->>",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR ? (
  FUNCTION = eql_v3."?",
  LEFTARG = eql_v3.float4, RIGHTARG = text
);

CREATE OPERATOR ?| (
  FUNCTION = eql_v3."?|",
  LEFTARG = eql_v3.float4, RIGHTARG = text[]
);

CREATE OPERATOR ?& (
  FUNCTION = eql_v3."?&",
  LEFTARG = eql_v3.float4, RIGHTARG = text[]
);

CREATE OPERATOR @? (
  FUNCTION = eql_v3."@?",
  LEFTARG = eql_v3.float4, RIGHTARG = jsonpath
);

CREATE OPERATOR @@ (
  FUNCTION = eql_v3."@@",
  LEFTARG = eql_v3.float4, RIGHTARG = jsonpath
);

CREATE OPERATOR #> (
  FUNCTION = eql_v3."#>",
  LEFTARG = eql_v3.float4, RIGHTARG = text[]
);

CREATE OPERATOR #>> (
  FUNCTION = eql_v3."#>>",
  LEFTARG = eql_v3.float4, RIGHTARG = text[]
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4, RIGHTARG = text
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4, RIGHTARG = integer
);

CREATE OPERATOR - (
  FUNCTION = eql_v3."-",
  LEFTARG = eql_v3.float4, RIGHTARG = text[]
);

CREATE OPERATOR #- (
  FUNCTION = eql_v3."#-",
  LEFTARG = eql_v3.float4, RIGHTARG = text[]
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4, RIGHTARG = eql_v3.float4
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = eql_v3.float4, RIGHTARG = jsonb
);

CREATE OPERATOR || (
  FUNCTION = eql_v3."||",
  LEFTARG = jsonb, RIGHTARG = eql_v3.float4
);

--! @file v3/sem/ore_cllw/operators.sql
--! @brief Comparison operators on the eql_v3.ore_cllw composite type.
--!
--! Each backing function reduces to a single SELECT over
--! eql_v3.compare_ore_cllw_term(a, b) and is inlinable so the planner can fold
--! it through to functional-index matching. The inner comparator is plpgsql
--! (per-byte loop) and is not inlined — fine for index *match*.
--!
--! @note Deliberately no HASHES / MERGES — the CLLW protocol gives ordering,
--!       not a hash; there is no merge-joinable opclass on the other side.
--! @see eql_v3.compare_ore_cllw_term

--! @brief Equality backing function for eql_v3.ore_cllw.
--! @internal
--!
--! @param a eql_v3.ore_cllw Left operand
--! @param b eql_v3.ore_cllw Right operand
--! @return boolean True if the CLLW ORE terms are equal
--!
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw_eq(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_cllw_term(a, b) = 0
$$;

--! @brief Not-equal backing function for eql_v3.ore_cllw.
--! @internal
--!
--! @param a eql_v3.ore_cllw Left operand
--! @param b eql_v3.ore_cllw Right operand
--! @return boolean True if the CLLW ORE terms are not equal
--!
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw_neq(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_cllw_term(a, b) <> 0
$$;

--! @brief Less-than backing function for eql_v3.ore_cllw.
--! @internal
--!
--! @param a eql_v3.ore_cllw Left operand
--! @param b eql_v3.ore_cllw Right operand
--! @return boolean True if the left operand is less than the right operand
--!
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw_lt(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_cllw_term(a, b) = -1
$$;

--! @brief Less-than-or-equal backing function for eql_v3.ore_cllw.
--! @internal
--!
--! @param a eql_v3.ore_cllw Left operand
--! @param b eql_v3.ore_cllw Right operand
--! @return boolean True if the left operand is less than or equal to the right operand
--!
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw_lte(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_cllw_term(a, b) <> 1
$$;

--! @brief Greater-than backing function for eql_v3.ore_cllw.
--! @internal
--!
--! @param a eql_v3.ore_cllw Left operand
--! @param b eql_v3.ore_cllw Right operand
--! @return boolean True if the left operand is greater than the right operand
--!
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw_gt(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_cllw_term(a, b) = 1
$$;

--! @brief Greater-than-or-equal backing function for eql_v3.ore_cllw.
--! @internal
--!
--! @param a eql_v3.ore_cllw Left operand
--! @param b eql_v3.ore_cllw Right operand
--! @return boolean True if the left operand is greater than or equal to the right operand
--!
--! @see eql_v3.compare_ore_cllw_term
CREATE FUNCTION eql_v3.ore_cllw_gte(a eql_v3.ore_cllw, b eql_v3.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_cllw_term(a, b) <> -1
$$;


CREATE OPERATOR = (
  FUNCTION = eql_v3.ore_cllw_eq,
  LEFTARG = eql_v3.ore_cllw,
  RIGHTARG = eql_v3.ore_cllw,
  COMMUTATOR = =,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.ore_cllw_neq,
  LEFTARG = eql_v3.ore_cllw,
  RIGHTARG = eql_v3.ore_cllw,
  COMMUTATOR = <>,
  NEGATOR = =,
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.ore_cllw_lt,
  LEFTARG = eql_v3.ore_cllw,
  RIGHTARG = eql_v3.ore_cllw,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.ore_cllw_lte,
  LEFTARG = eql_v3.ore_cllw,
  RIGHTARG = eql_v3.ore_cllw,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.ore_cllw_gt,
  LEFTARG = eql_v3.ore_cllw,
  RIGHTARG = eql_v3.ore_cllw,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.ore_cllw_gte,
  LEFTARG = eql_v3.ore_cllw,
  RIGHTARG = eql_v3.ore_cllw,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

--! @file v3/jsonb/aggregates.sql
--! @brief min / max aggregates over eql_v3.ste_vec_entry.
--!
--! SteVec document entries extracted at a selector (`doc -> 'sel'`) order by
--! their CLLW ORE (`oc`) term, so the extremum is picked by comparing
--! `eql_v3.ore_cllw(entry)` rather than the scalar Block-ORE `ord_term` the
--! generated scalar ord aggregates use. Same STRICT + PARALLEL SAFE shape as the
--! generated scalar `min`/`max` so partial/parallel aggregation is available on
--! large GROUP BY workloads.
--!
--! Per the encrypted-domain footgun rules the state functions are
--! `LANGUAGE plpgsql` with the pinned `search_path` — a `LANGUAGE sql` body would
--! be inlinable and the planner could elide it.
--!
--! @note **Only `oc`-carrying entries are orderable.** `eql_v3.ore_cllw(entry)`
--!   returns NULL when an entry has no `oc` (CLLW ORE) term — the same entries a
--!   `eql_v3.ore_cllw` btree NULL-filters from range scans. The state functions
--!   therefore IGNORE `oc`-less entries (they never become or survive as the
--!   extremum), so `min`/`max` is well-defined over a mix of `oc`-carrying and
--!   `oc`-less entries and is not corrupted by an `oc`-less seed. A naive
--!   `ore_cllw(value) < ore_cllw(state)` would be NULL whenever either side
--!   lacks `oc`, pinning a wrong (`oc`-less) extremum when the first aggregated
--!   row is `oc`-less. An all-`oc`-less input has no orderable extremum and
--!   returns the (arbitrary) STRICT seed.

--! @brief State function for min on eql_v3.ste_vec_entry.
--!
--! Keeps whichever orderable entry has the lesser CLLW ORE term. STRICT, so SQL
--! NULL entries are skipped by the aggregate machinery; `oc`-less (non-orderable)
--! entries are skipped explicitly (see the @note on this file).
--!
--! @param state eql_v3.ste_vec_entry Running extremum.
--! @param value eql_v3.ste_vec_entry Candidate entry.
--! @return eql_v3.ste_vec_entry The lesser orderable entry by `ore_cllw`.
CREATE FUNCTION eql_v3.ste_vec_entry_min_sfunc(
  state eql_v3.ste_vec_entry,
  value eql_v3.ste_vec_entry
)
RETURNS eql_v3.ste_vec_entry
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  value_ore eql_v3.ore_cllw := eql_v3.ore_cllw(value);
  state_ore eql_v3.ore_cllw := eql_v3.ore_cllw(state);
BEGIN
  -- A non-orderable (oc-less) candidate never replaces the running extremum.
  IF value_ore IS NULL THEN
    RETURN state;
  END IF;
  -- Adopt the candidate when the running extremum is itself non-orderable
  -- (e.g. an oc-less STRICT seed) or strictly greater.
  IF state_ore IS NULL OR value_ore < state_ore THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief min aggregate over eql_v3.ste_vec_entry.
--! @param input eql_v3.ste_vec_entry
--! @return eql_v3.ste_vec_entry The entry with the smallest CLLW ORE term.
CREATE AGGREGATE eql_v3.min(eql_v3.ste_vec_entry) (
  sfunc = eql_v3.ste_vec_entry_min_sfunc,
  stype = eql_v3.ste_vec_entry,
  combinefunc = eql_v3.ste_vec_entry_min_sfunc,
  parallel = safe
);

--! @brief State function for max on eql_v3.ste_vec_entry.
--!
--! Keeps whichever orderable entry has the greater CLLW ORE term. `oc`-less
--! entries are skipped, mirroring `ste_vec_entry_min_sfunc` (see the file @note).
--!
--! @param state eql_v3.ste_vec_entry Running extremum.
--! @param value eql_v3.ste_vec_entry Candidate entry.
--! @return eql_v3.ste_vec_entry The greater orderable entry by `ore_cllw`.
CREATE FUNCTION eql_v3.ste_vec_entry_max_sfunc(
  state eql_v3.ste_vec_entry,
  value eql_v3.ste_vec_entry
)
RETURNS eql_v3.ste_vec_entry
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  value_ore eql_v3.ore_cllw := eql_v3.ore_cllw(value);
  state_ore eql_v3.ore_cllw := eql_v3.ore_cllw(state);
BEGIN
  -- A non-orderable (oc-less) candidate never replaces the running extremum.
  IF value_ore IS NULL THEN
    RETURN state;
  END IF;
  -- Adopt the candidate when the running extremum is itself non-orderable
  -- (e.g. an oc-less STRICT seed) or strictly lesser.
  IF state_ore IS NULL OR value_ore > state_ore THEN
    RETURN value;
  END IF;
  RETURN state;
END;
$$;

--! @brief max aggregate over eql_v3.ste_vec_entry.
--! @param input eql_v3.ste_vec_entry
--! @return eql_v3.ste_vec_entry The entry with the largest CLLW ORE term.
CREATE AGGREGATE eql_v3.max(eql_v3.ste_vec_entry) (
  sfunc = eql_v3.ste_vec_entry_max_sfunc,
  stype = eql_v3.ste_vec_entry,
  combinefunc = eql_v3.ste_vec_entry_max_sfunc,
  parallel = safe
);

--! @file v3/jsonb/operators.sql
--! @brief Operators on eql_v3.json and eql_v3.ste_vec_entry.

------------------------------------------------------------------------------
-- -> field accessor (returns ste_vec_entry)
------------------------------------------------------------------------------

--! @brief -> operator with text selector.
--!
--! Returns the sv entry whose `s` equals @p selector, with root `i`/`v` merged
--! in. Inlinable: `WHERE col -> 'sel' = $1` reduces structurally to
--! `eql_v3.eq_term(col -> 'sel') = eql_v3.eq_term($1)` and matches a functional
--! index on `eql_v3.eq_term(col -> 'sel')`.
--!
--! @warning The selector operand MUST carry a known type — a text-typed
--!   parameter (`$1`, the Proxy interface) or an explicit cast (`col -> 'sel'::text`).
--!   A bare untyped literal (`col -> 'sel'`) resolves to the NATIVE `jsonb -> text`
--!   operator and silently returns native jsonb semantics (a root-key lookup,
--!   typically NULL), NOT this operator: PostgreSQL reduces the `eql_v3.json`
--!   domain to its base type `jsonb` when resolving an unknown-typed RHS, and the
--!   native base-type operator wins the exact-match tiebreak. This is intrinsic to
--!   the domain type-kind and applies to the native-jsonb blockers too. See
--!   the "Typed operands" caveat in docs/reference/json-support.md.
--!
--! @param e eql_v3.json Root encrypted payload.
--! @param selector text Selector hash.
--! @return eql_v3.ste_vec_entry Matching entry merged with root meta, or NULL.
CREATE FUNCTION eql_v3."->"(e eql_v3.json, selector text)
  RETURNS eql_v3.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (
    eql_v3.meta_data(e) ||
    jsonb_path_query_first(
      e,
      '$.sv[*] ? (@.s == $sel)'::jsonpath,
      jsonb_build_object('sel', selector)
    )
  )::eql_v3.ste_vec_entry
$$;

CREATE OPERATOR ->(
  FUNCTION=eql_v3."->",
  LEFTARG=eql_v3.json,
  RIGHTARG=text
);

--! @brief -> operator with integer array index (0-based, JSONB convention).
--! @param e eql_v3.json Encrypted sv-array payload.
--! @param selector integer Array index.
--! @return eql_v3.ste_vec_entry Matching entry merged with root meta, or NULL.
CREATE FUNCTION eql_v3."->"(e eql_v3.json, selector integer)
  RETURNS eql_v3.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN eql_v3.is_ste_vec_array(e) THEN
      -- `->(eql_v3.json, text)` operator is already created earlier in
      -- this file, so a bare `e -> 'sv'` would resolve to that selector-lookup
      -- operator (searching for an sv entry with selector 'sv') instead of
      -- native jsonb array access. Casting to jsonb forces native `->`.
      (eql_v3.meta_data(e) || (e::jsonb -> 'sv' -> selector))::eql_v3.ste_vec_entry
    ELSE NULL
  END
$$;

CREATE OPERATOR ->(
  FUNCTION=eql_v3."->",
  LEFTARG=eql_v3.json,
  RIGHTARG=integer
);

------------------------------------------------------------------------------
-- ->> field accessor (alias of -> coerced to text)
------------------------------------------------------------------------------

--! @brief ->> operator with text selector. Inlinable alias of -> coerced to
--!        text.
--!
--! Intentional v2 parity: this serializes the entire matched ste_vec_entry
--! object as JSON text. It does not decrypt or return scalar plaintext like
--! native `jsonb ->>`.
--! @param e eql_v3.json Encrypted payload.
--! @param selector text Field selector hash.
--! @return text The matching entry as text.
CREATE FUNCTION eql_v3."->>"(e eql_v3.json, selector text)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION=eql_v3."->>",
  LEFTARG=eql_v3.json,
  RIGHTARG=text
);

--! @brief ->> operator with integer array index. Inlinable alias of
--!        ->(json, integer) coerced to text.
--! @param e eql_v3.json Encrypted sv-array payload.
--! @param selector integer Array index.
--! @return text The matching entry as text.
CREATE FUNCTION eql_v3."->>"(e eql_v3.json, selector integer)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."->"(e, selector)::jsonb::text
$$;

CREATE OPERATOR ->> (
  FUNCTION=eql_v3."->>",
  LEFTARG=eql_v3.json,
  RIGHTARG=integer
);

------------------------------------------------------------------------------
-- @> containment
------------------------------------------------------------------------------

--! @brief @> contains operator (document, document).
--! @param a eql_v3.json Container.
--! @param b eql_v3.json Contained value.
--! @return boolean True if a contains b.
--! @see eql_v3.ste_vec_contains
CREATE FUNCTION eql_v3."@>"(a eql_v3.json, b eql_v3.json)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ste_vec_contains(a, b)
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v3."@>",
  LEFTARG=eql_v3.json,
  RIGHTARG=eql_v3.json
);

--! @brief @> contains operator with an ste_vec_query needle.
--!
--! Inlines to native `jsonb @>` over `eql_v3.to_ste_vec_query(a)::jsonb`, so a
--! functional GIN index on the same expression engages.
--!
--! @param a eql_v3.json Container.
--! @param b eql_v3.ste_vec_query Query payload.
--! @return boolean True if a contains b.
CREATE FUNCTION eql_v3."@>"(a eql_v3.json, b eql_v3.ste_vec_query)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.to_ste_vec_query(a)::jsonb @> b::jsonb
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v3."@>",
  LEFTARG=eql_v3.json,
  RIGHTARG=eql_v3.ste_vec_query
);

--! @brief @> contains operator with a single ste_vec_entry needle.
--!
--! Wraps the entry into a single-element sv array (stripping `c`) and reduces
--! to the same `to_ste_vec_query(a)::jsonb @> needle::jsonb` form.
--!
--! @param a eql_v3.json Container.
--! @param b eql_v3.ste_vec_entry Single entry.
--! @return boolean True if a contains an sv entry matching b.
CREATE FUNCTION eql_v3."@>"(a eql_v3.json, b eql_v3.ste_vec_entry)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.to_ste_vec_query(a)::jsonb
       @> jsonb_build_object(
            'sv',
            jsonb_build_array(
              jsonb_strip_nulls(
                jsonb_build_object(
                  's',  b -> 's',
                  'hm', b -> 'hm',
                  'oc', b -> 'oc'
                )
              )
            )
          )
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v3."@>",
  LEFTARG=eql_v3.json,
  RIGHTARG=eql_v3.ste_vec_entry
);

------------------------------------------------------------------------------
-- <@ contained-by (reverse of @>)
------------------------------------------------------------------------------

--! @brief <@ contained-by operator (document, document).
--! @param a eql_v3.json Contained value.
--! @param b eql_v3.json Container.
--! @return boolean True if a is contained by b.
CREATE FUNCTION eql_v3."<@"(a eql_v3.json, b eql_v3.json)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ste_vec_contains(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v3."<@",
  LEFTARG=eql_v3.json,
  RIGHTARG=eql_v3.json
);

--! @brief <@ contained-by operator with an ste_vec_query LHS.
--! @param a eql_v3.ste_vec_query Query payload.
--! @param b eql_v3.json Container.
--! @return boolean True if b contains a.
CREATE FUNCTION eql_v3."<@"(a eql_v3.ste_vec_query, b eql_v3.json)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."@>"(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v3."<@",
  LEFTARG=eql_v3.ste_vec_query,
  RIGHTARG=eql_v3.json
);

--! @brief <@ contained-by operator with a ste_vec_entry LHS.
--! @param a eql_v3.ste_vec_entry Single entry.
--! @param b eql_v3.json Container.
--! @return boolean True if b contains a.
CREATE FUNCTION eql_v3."<@"(a eql_v3.ste_vec_entry, b eql_v3.json)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3."@>"(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v3."<@",
  LEFTARG=eql_v3.ste_vec_entry,
  RIGHTARG=eql_v3.json
);

------------------------------------------------------------------------------
-- ste_vec_entry comparisons
------------------------------------------------------------------------------

--! @brief Equality on ste_vec_entry via eq_term (hm-or-oc byte equality).
--! @internal
--! @param a eql_v3.ste_vec_entry Left operand
--! @param b eql_v3.ste_vec_entry Right operand
--! @return boolean True if the entries are equal
CREATE FUNCTION eql_v3.eq(a eql_v3.ste_vec_entry, b eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.eq_term(a) = eql_v3.eq_term(b)
$$;

CREATE OPERATOR = (
  FUNCTION = eql_v3.eq,
  LEFTARG  = eql_v3.ste_vec_entry,
  RIGHTARG = eql_v3.ste_vec_entry,
  COMMUTATOR = =,
  NEGATOR  = <>,
  RESTRICT = eqsel,
  JOIN     = eqjoinsel
);

--! @brief Inequality on ste_vec_entry via eq_term.
--! @internal
--! @param a eql_v3.ste_vec_entry Left operand
--! @param b eql_v3.ste_vec_entry Right operand
--! @return boolean True if the entries are not equal
CREATE FUNCTION eql_v3.neq(a eql_v3.ste_vec_entry, b eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.eq_term(a) <> eql_v3.eq_term(b)
$$;

CREATE OPERATOR <> (
  FUNCTION = eql_v3.neq,
  LEFTARG  = eql_v3.ste_vec_entry,
  RIGHTARG = eql_v3.ste_vec_entry,
  COMMUTATOR = <>,
  NEGATOR  = =,
  RESTRICT = neqsel,
  JOIN     = neqjoinsel
);

--! @brief Less-than on ste_vec_entry via ore_cllw.
--! @internal
--! @param a eql_v3.ste_vec_entry Left operand
--! @param b eql_v3.ste_vec_entry Right operand
--! @return boolean True if a is less than b
CREATE FUNCTION eql_v3.lt(a eql_v3.ste_vec_entry, b eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ore_cllw(a) < eql_v3.ore_cllw(b)
$$;

CREATE OPERATOR < (
  FUNCTION = eql_v3.lt,
  LEFTARG  = eql_v3.ste_vec_entry,
  RIGHTARG = eql_v3.ste_vec_entry,
  COMMUTATOR = >,
  NEGATOR  = >=,
  RESTRICT = scalarltsel,
  JOIN     = scalarltjoinsel
);

--! @brief Less-than-or-equal on ste_vec_entry via ore_cllw.
--! @internal
--! @param a eql_v3.ste_vec_entry Left operand
--! @param b eql_v3.ste_vec_entry Right operand
--! @return boolean True if a is less than or equal to b
CREATE FUNCTION eql_v3.lte(a eql_v3.ste_vec_entry, b eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ore_cllw(a) <= eql_v3.ore_cllw(b)
$$;

CREATE OPERATOR <= (
  FUNCTION = eql_v3.lte,
  LEFTARG  = eql_v3.ste_vec_entry,
  RIGHTARG = eql_v3.ste_vec_entry,
  COMMUTATOR = >=,
  NEGATOR  = >,
  RESTRICT = scalarlesel,
  JOIN     = scalarlejoinsel
);

--! @brief Greater-than on ste_vec_entry via ore_cllw.
--! @internal
--! @param a eql_v3.ste_vec_entry Left operand
--! @param b eql_v3.ste_vec_entry Right operand
--! @return boolean True if a is greater than b
CREATE FUNCTION eql_v3.gt(a eql_v3.ste_vec_entry, b eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ore_cllw(a) > eql_v3.ore_cllw(b)
$$;

CREATE OPERATOR > (
  FUNCTION = eql_v3.gt,
  LEFTARG  = eql_v3.ste_vec_entry,
  RIGHTARG = eql_v3.ste_vec_entry,
  COMMUTATOR = <,
  NEGATOR  = <=,
  RESTRICT = scalargtsel,
  JOIN     = scalargtjoinsel
);

--! @brief Greater-than-or-equal on ste_vec_entry via ore_cllw.
--! @internal
--! @param a eql_v3.ste_vec_entry Left operand
--! @param b eql_v3.ste_vec_entry Right operand
--! @return boolean True if a is greater than or equal to b
CREATE FUNCTION eql_v3.gte(a eql_v3.ste_vec_entry, b eql_v3.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.ore_cllw(a) >= eql_v3.ore_cllw(b)
$$;

CREATE OPERATOR >= (
  FUNCTION = eql_v3.gte,
  LEFTARG  = eql_v3.ste_vec_entry,
  RIGHTARG = eql_v3.ste_vec_entry,
  COMMUTATOR = <=,
  NEGATOR  = <,
  RESTRICT = scalargesel,
  JOIN     = scalargejoinsel
);

--! @file v3/jsonb/blockers.sql
--! @brief Native-jsonb firewall for eql_v3.json.
--!
--! eql_v3.json SUPPORTS @> <@ -> ->> (see operators.sql). Comparisons
--! = <> < <= > >= are supported on eql_v3.ste_vec_entry only, not on the root
--! document domain.
--! Every OTHER native jsonb operator reachable via domain fallback against the
--! base type jsonb is BLOCKED here so an encrypted column can never silently
--! route to plaintext-jsonb semantics. The blocked set is KNOWN_JSONB_OPERATORS
--! minus the supported ops: ? ?| ?& @? @@ #> #>> - #- ||.
--!
--! Each blocker is LANGUAGE plpgsql (NEVER STRICT — a STRICT blocker would let
--! PostgreSQL skip the body and return NULL on a NULL argument, bypassing the
--! exception) and delegates to the shared eql_v3.encrypted_domain_unsupported_*
--! helpers. Each blocker's RETURNS type matches the native operator it shadows
--! (#> -> jsonb, #>> -> text, - / #- / || -> jsonb; the rest are boolean) so a
--! composed expression resolves and the body raises 'operator not supported',
--! rather than failing earlier with a misleading 'operator does not exist' on a
--! boolean intermediate. The bound operator must resolve before native fallback,
--! so the firewall fires.

--! @brief Blocker: ? (key/element exists).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_exists(a eql_v3.json, b text)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '?');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ? (
  FUNCTION = eql_v3.jsonb_blocked_exists,
  LEFTARG = eql_v3.json,
  RIGHTARG = text
);

--! @brief Blocker: ?| (any key exists).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_exists_any(a eql_v3.json, b text[])
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '?|');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ?| (
  FUNCTION = eql_v3.jsonb_blocked_exists_any,
  LEFTARG = eql_v3.json,
  RIGHTARG = text[]
);

--! @brief Blocker: ?& (all keys exist).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_exists_all(a eql_v3.json, b text[])
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '?&');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ?& (
  FUNCTION = eql_v3.jsonb_blocked_exists_all,
  LEFTARG = eql_v3.json,
  RIGHTARG = text[]
);

--! @brief Blocker: @? (jsonpath exists).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b jsonpath Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_jsonpath_exists(a eql_v3.json, b jsonpath)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '@?');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @? (
  FUNCTION = eql_v3.jsonb_blocked_jsonpath_exists,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonpath
);

--! @brief Blocker: @@ (jsonpath predicate).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b jsonpath Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_jsonpath_match(a eql_v3.json, b jsonpath)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '@@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @@ (
  FUNCTION = eql_v3.jsonb_blocked_jsonpath_match,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonpath
);

--! @brief Blocker: #> (path extract, native returns jsonb).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_path_extract(a eql_v3.json, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '#>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #> (
  FUNCTION = eql_v3.jsonb_blocked_path_extract,
  LEFTARG = eql_v3.json,
  RIGHTARG = text[]
);

--! @brief Blocker: #>> (path extract as text).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return text Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_path_extract_text(a eql_v3.json, b text[])
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_text('eql_v3.json', '#>>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #>> (
  FUNCTION = eql_v3.jsonb_blocked_path_extract_text,
  LEFTARG = eql_v3.json,
  RIGHTARG = text[]
);

--! @brief Blocker: - (delete key, text RHS; native returns jsonb).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_delete_text(a eql_v3.json, b text)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = eql_v3.jsonb_blocked_delete_text,
  LEFTARG = eql_v3.json,
  RIGHTARG = text
);

--! @brief Blocker: - (delete index, integer RHS).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b integer Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_delete_int(a eql_v3.json, b integer)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = eql_v3.jsonb_blocked_delete_int,
  LEFTARG = eql_v3.json,
  RIGHTARG = integer
);

--! @brief Blocker: - (delete keys, text[] RHS).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_delete_array(a eql_v3.json, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = eql_v3.jsonb_blocked_delete_array,
  LEFTARG = eql_v3.json,
  RIGHTARG = text[]
);

--! @brief Blocker: #- (delete at path).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_delete_path(a eql_v3.json, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '#-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #- (
  FUNCTION = eql_v3.jsonb_blocked_delete_path,
  LEFTARG = eql_v3.json,
  RIGHTARG = text[]
);

--! @brief Blocker: || (concatenate, encrypted on the left).
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_concat(a eql_v3.json, b jsonb)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '||');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR || (
  FUNCTION = eql_v3.jsonb_blocked_concat,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

--! @brief Blocker: || (concatenate, encrypted on the right).
--! @param a jsonb Native LHS operand.
--! @param b eql_v3.json Right operand (encrypted payload).
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_concat_rhs(a jsonb, b eql_v3.json)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_jsonb('eql_v3.json', '||');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR || (
  FUNCTION = eql_v3.jsonb_blocked_concat_rhs,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

------------------------------------------------------------------------------
-- Root-document comparison blockers.
------------------------------------------------------------------------------

--! @brief Blocker: root eql_v3.json document comparisons.
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b eql_v3.json Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_compare_json_json(a eql_v3.json, b eql_v3.json)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', 'comparison');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: root eql_v3.json-to-jsonb comparisons.
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_compare_json_jsonb(a eql_v3.json, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', 'comparison');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: root jsonb-to-eql_v3.json comparisons.
--! @param a jsonb Native LHS operand.
--! @param b eql_v3.json Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_compare_jsonb_json(a jsonb, b eql_v3.json)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', 'comparison');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_json,
  LEFTARG = eql_v3.json,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_json,
  LEFTARG = eql_v3.json,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_json,
  LEFTARG = eql_v3.json,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_json,
  LEFTARG = eql_v3.json,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_json,
  LEFTARG = eql_v3.json,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_json,
  LEFTARG = eql_v3.json,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.jsonb_blocked_compare_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

------------------------------------------------------------------------------
-- Mixed jsonb containment blockers.
------------------------------------------------------------------------------

--! @brief Blocker: @> with encrypted root document and native jsonb.
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_contains_json_jsonb(a eql_v3.json, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '@>');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: @> with native jsonb and encrypted root document.
--! @param a jsonb Native LHS operand.
--! @param b eql_v3.json Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_contains_jsonb_json(a jsonb, b eql_v3.json)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '@>');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: <@ with encrypted root document and native jsonb.
--! @param a eql_v3.json Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_contained_json_jsonb(a eql_v3.json, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '<@');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: <@ with native jsonb and encrypted root document.
--! @param a jsonb Native LHS operand.
--! @param b eql_v3.json Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3.jsonb_blocked_contained_jsonb_json(a jsonb, b eql_v3.json)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3.encrypted_domain_unsupported_bool('eql_v3.json', '<@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @> (
  FUNCTION = eql_v3.jsonb_blocked_contains_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3.jsonb_blocked_contains_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.jsonb_blocked_contained_json_jsonb,
  LEFTARG = eql_v3.json,
  RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3.jsonb_blocked_contained_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = eql_v3.json
);
