// @generated — DO NOT EDIT.
// Source: scripts/vendor-eql-v3-install.ts
// Origin fixture: __tests__/fixtures/cipherstash-encrypt-v3.sql
//
// This file is committed to source control so dev environments and offline
// builds work without network access. Regenerate with
// `pnpm tsx scripts/vendor-eql-v3-install.ts` after refreshing the fixture.
export const EQL_V3_INSTALL_VERSION = 'eql-v3-035952e' as const
export const EQL_V3_INSTALL_SQL: string = `--! @file v3/schema.sql
--! @brief EQL v3 schema creation
--!
--! Creates the eql_v3 schema, which houses the self-contained encrypted-domain
--! type families (eql_v3.int4, eql_v3.int8, and future scalar domains): their
--! jsonb-backed domains, the searchable-encrypted-metadata (SEM) index-term
--! types they use (eql_v3.hmac_256, eql_v3.ore_block_u64_8_256), the index-term
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

--! @file v3/sem/ore_block_u64_8_256/types.sql
--! @brief ORE block index-term types (eql_v3 SEM).
--!
--! Self-contained eql_v3 copies of the Order-Revealing Encryption block types
--! (design D1/D3). The eql_v2 originals are unchanged.

--! @brief ORE block term type for Order-Revealing Encryption
--!
--! Composite type representing a single ORE block term. Stores encrypted data
--! as bytea that enables range comparisons without decryption.
CREATE TYPE eql_v3.ore_block_u64_8_256_term AS (
  bytes bytea
);


--! @brief ORE block index term type for range queries
--!
--! Composite type containing an array of ORE block terms. The array is stored
--! in the 'ob' field of encrypted data payloads.
--!
--! @note Transient type used only during query execution.
CREATE TYPE eql_v3.ore_block_u64_8_256 AS (
  terms eql_v3.ore_block_u64_8_256_term[]
);

--! @file v3/crypto.sql
--! @brief PostgreSQL pgcrypto extension enablement (eql_v3 fork)
--!
--! Forked from src/crypto.sql (design D8) so the entire eql_v3 dependency
--! closure lives under src/v3/. Enables the pgcrypto extension which provides
--! cryptographic functions used by the eql_v3 ORE comparison path.
--!
--! Installs pgcrypto into the \`extensions\` schema (Supabase convention) to
--! avoid the \`extension_in_public\` lint. Every EQL function that uses pgcrypto
--! has \`pg_catalog, extensions, public\` on its \`search_path\`, so a pre-existing
--! install in \`public\` keeps working — and a pre-existing install anywhere else
--! will be rejected at install time. The body is idempotent
--! (\`CREATE SCHEMA IF NOT EXISTS\`, \`pg_extension\` guard), so running it
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
      'pgcrypto is installed in the \`public\` schema. EQL works against this layout, '
      'but Supabase splinter will flag it as \`extension_in_public\`. Move it with: '
      'ALTER EXTENSION pgcrypto SET SCHEMA extensions';
  ELSE
    RAISE EXCEPTION
      'pgcrypto is installed in schema \`%\`, which is not on the EQL function search_path '
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
--! @note Inlinable \`LANGUAGE sql\` IMMUTABLE form (no \`SET search_path\`) so the
--!   planner can fold this per-encrypted-value helper into the calling query.
--!   This deliberately diverges from the v2 plpgsql equivalent (intentionally
--!   left unchanged): the \`CASE WHEN jsonb_typeof(val) = 'array'\` guard only
--!   evaluates the set-returning \`jsonb_array_elements_text\` for an array, so a
--!   non-array JSON scalar returns NULL here instead of raising "cannot extract
--!   elements from a scalar". Both callers only ever pass an array or JSON null
--!   (\`val->'ob'\`), so the divergence is unreachable in practice; JSON null and
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
--! pin_search_path pass leaves it unpinned (no \`SET search_path\`), preserving
--! SQL-function inlining. It takes a bare \`jsonb\` arg (not a jsonb-backed
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
--! Backs the \`match\` capability (\`@>\` / \`<@\`) on \`eql_v3.text_match\`. The
--! filter is read from the \`bf\` field of an encrypted jsonb payload. Native
--! \`smallint[]\` array-containment (\`@>\`/\`<@\`) is inherited through the domain,
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

--! @file v3/sem/ore_block_u64_8_256/functions.sql
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
--! @return eql_v3.ore_block_u64_8_256 ORE block composite, or NULL if input is null
--! @note Inlinable \`LANGUAGE sql\` IMMUTABLE form (no \`SET search_path\`) so the
--!   planner can fold this per-encrypted-value helper into the calling query.
--!   This deliberately diverges from the v2 plpgsql equivalent (intentionally
--!   left unchanged): the \`CASE WHEN jsonb_typeof(val) = 'array'\` guard only
--!   evaluates the array path for an array, so a non-array JSON scalar returns
--!   NULL here instead of raising. The sole caller passes \`val->'ob'\`, always an
--!   array or JSON null, so the divergence is unreachable in practice; JSON null
--!   and empty array still return NULL exactly as before.
CREATE FUNCTION eql_v3.jsonb_array_to_ore_block_u64_8_256(val jsonb)
RETURNS eql_v3.ore_block_u64_8_256
  IMMUTABLE
AS $$
  SELECT CASE WHEN jsonb_typeof(val) = 'array'
    THEN ROW((
      SELECT array_agg(ROW(b)::eql_v3.ore_block_u64_8_256_term)
      FROM unnest(eql_v3.jsonb_array_to_bytea_array(val)) AS b
    ))::eql_v3.ore_block_u64_8_256
    ELSE NULL
  END;
$$ LANGUAGE sql;

--! @internal Mark this hand-written helper inline-critical so the post-install
--! pin_search_path pass leaves it unpinned (no \`SET search_path\`), preserving
--! SQL-function inlining. It takes a bare \`jsonb\` arg (not a jsonb-backed
--! encrypted DOMAIN), so the structural skip in tasks/pin_search_path.sql does
--! not recognise it; this marker is the documented manual opt-in.
COMMENT ON FUNCTION eql_v3.jsonb_array_to_ore_block_u64_8_256(jsonb) IS
  'eql-inline-critical: per-encrypted-value ORE helper; must stay inlinable (unpinned search_path)';


--! @brief Extract ORE block index term from JSONB payload
--! @param val jsonb containing encrypted EQL payload
--! @return eql_v3.ore_block_u64_8_256 ORE block index term
--! @throws Exception if 'ob' field is missing
CREATE FUNCTION eql_v3.ore_block_u64_8_256(val jsonb)
  RETURNS eql_v3.ore_block_u64_8_256
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    -- Declared STRICT: PostgreSQL returns NULL for a NULL argument without
    -- entering the body, so no explicit \`val IS NULL\` guard is needed.
    IF eql_v3.has_ore_block_u64_8_256(val) THEN
      RETURN eql_v3.jsonb_array_to_ore_block_u64_8_256(val->'ob');
    END IF;
    RAISE 'Expected an ore index (ob) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if JSONB payload contains ORE block index term
--! @param val jsonb containing encrypted EQL payload
--! @return boolean True if 'ob' field is present and non-null
CREATE FUNCTION eql_v3.has_ore_block_u64_8_256(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN val ->> 'ob' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;


--! @brief Compare two ORE block terms using cryptographic comparison
--! @internal
--! @param a eql_v3.ore_block_u64_8_256_term First ORE term
--! @param b eql_v3.ore_block_u64_8_256_term Second ORE term
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
--! @throws Exception if ciphertexts are different lengths
--! @note Marked \`IMMUTABLE\` (the three \`compare_ore_block_u64_8_256_term(s)\`
--!   overloads all are). This deliberately diverges from the v2 originals,
--!   which carry no volatility marker and so default to \`VOLATILE\`. The
--!   comparison is deterministic — its only crypto call, pgcrypto \`encrypt()\`,
--!   is itself \`IMMUTABLE STRICT PARALLEL SAFE\` — so \`IMMUTABLE\` lets the
--!   planner fold/cache these in ordering and index contexts. NOT \`STRICT\`:
--!   the NULL-handling branches below are load-bearing for the array overload.
CREATE FUNCTION eql_v3.compare_ore_block_u64_8_256_term(a eql_v3.ore_block_u64_8_256_term, b eql_v3.ore_block_u64_8_256_term)
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
    right_offset CONSTANT smallint := 136; -- 8 * 17

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

    FOR block IN 0..7 LOOP
      IF
        substr(a.bytes, 1 + block, 1) != substr(b.bytes, 1 + block, 1)
        OR substr(a.bytes, 9 + left_block_size * block, left_block_size) != substr(b.bytes, 9 + left_block_size * BLOCK, left_block_size)
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

    hash_key := substr(b.bytes, right_offset + 1, 16);

    target_block := substr(b.bytes, right_offset + 17 + (unequal_block * right_block_size), right_block_size);

    data_block := substr(a.bytes, 9 + (left_block_size * unequal_block), left_block_size);

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
--! @param a eql_v3.ore_block_u64_8_256_term[] First array
--! @param b eql_v3.ore_block_u64_8_256_term[] Second array
--! @return integer -1/0/1, or NULL if either array is NULL
CREATE FUNCTION eql_v3.compare_ore_block_u64_8_256_terms(a eql_v3.ore_block_u64_8_256_term[], b eql_v3.ore_block_u64_8_256_term[])
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

    cmp_result := eql_v3.compare_ore_block_u64_8_256_term(a[1], b[1]);

    IF cmp_result = 0 THEN
      RETURN eql_v3.compare_ore_block_u64_8_256_terms(a[2:array_length(a,1)], b[2:array_length(b,1)]);
    END IF;

    RETURN cmp_result;
  END
$$ LANGUAGE plpgsql;


--! @brief Compare ORE block composite types
--! @internal
--! @param a eql_v3.ore_block_u64_8_256 First ORE block
--! @param b eql_v3.ore_block_u64_8_256 Second ORE block
--! @return integer -1/0/1
CREATE FUNCTION eql_v3.compare_ore_block_u64_8_256_terms(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS integer
  IMMUTABLE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v3.compare_ore_block_u64_8_256_terms(a.terms, b.terms);
  END
$$ LANGUAGE plpgsql;

--! @file v3/sem/ore_block_u64_8_256/operators.sql
--! @brief Comparison operators on eql_v3.ore_block_u64_8_256.
--!
--! The six backing functions are inlinable single-statement SQL so the planner
--! can fold the eql_v3 comparison wrappers through to functional-index matching.

--! @brief Equality backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_u64_8_256 Left operand
--! @param b eql_v3.ore_block_u64_8_256 Right operand
--! @return boolean True if the ORE blocks are equal
--!
--! @see eql_v3.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v3.ore_block_u64_8_256_eq(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_u64_8_256_terms(a, b) = 0
$$;

--! @brief Not-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_u64_8_256 Left operand
--! @param b eql_v3.ore_block_u64_8_256 Right operand
--! @return boolean True if the ORE blocks are not equal
--!
--! @see eql_v3.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v3.ore_block_u64_8_256_neq(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_u64_8_256_terms(a, b) <> 0
$$;

--! @brief Less-than backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_u64_8_256 Left operand
--! @param b eql_v3.ore_block_u64_8_256 Right operand
--! @return boolean True if the left operand is less than the right operand
--!
--! @see eql_v3.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v3.ore_block_u64_8_256_lt(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_u64_8_256_terms(a, b) = -1
$$;

--! @brief Less-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_u64_8_256 Left operand
--! @param b eql_v3.ore_block_u64_8_256 Right operand
--! @return boolean True if the left operand is less than or equal to the right operand
--!
--! @see eql_v3.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v3.ore_block_u64_8_256_lte(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_u64_8_256_terms(a, b) != 1
$$;

--! @brief Greater-than backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_u64_8_256 Left operand
--! @param b eql_v3.ore_block_u64_8_256 Right operand
--! @return boolean True if the left operand is greater than the right operand
--!
--! @see eql_v3.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v3.ore_block_u64_8_256_gt(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_u64_8_256_terms(a, b) = 1
$$;

--! @brief Greater-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3.ore_block_u64_8_256 Left operand
--! @param b eql_v3.ore_block_u64_8_256 Right operand
--! @return boolean True if the left operand is greater than or equal to the right operand
--!
--! @see eql_v3.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v3.ore_block_u64_8_256_gte(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3.compare_ore_block_u64_8_256_terms(a, b) != -1
$$;


--! @brief = operator for ORE block types
--!
--! COMMUTATOR is the operator itself: equality is symmetric. Required for the
--! MERGES flag — without it the planner raises "could not find commutator" the
--! first time an ore_block equality is used as a join qual (e.g. via the inlined
--! eql_v3.<T>_ord_ore equality wrappers).
CREATE OPERATOR = (
  FUNCTION=eql_v3.ore_block_u64_8_256_eq,
  LEFTARG=eql_v3.ore_block_u64_8_256,
  RIGHTARG=eql_v3.ore_block_u64_8_256,
  COMMUTATOR = =,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

--! @brief <> operator for ORE block types
CREATE OPERATOR <> (
  FUNCTION=eql_v3.ore_block_u64_8_256_neq,
  LEFTARG=eql_v3.ore_block_u64_8_256,
  RIGHTARG=eql_v3.ore_block_u64_8_256,
  COMMUTATOR = <>,
  NEGATOR = =,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

--! @brief > operator for ORE block types
CREATE OPERATOR > (
  FUNCTION=eql_v3.ore_block_u64_8_256_gt,
  LEFTARG=eql_v3.ore_block_u64_8_256,
  RIGHTARG=eql_v3.ore_block_u64_8_256,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief < operator for ORE block types
CREATE OPERATOR < (
  FUNCTION=eql_v3.ore_block_u64_8_256_lt,
  LEFTARG=eql_v3.ore_block_u64_8_256,
  RIGHTARG=eql_v3.ore_block_u64_8_256,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief <= operator for ORE block types
CREATE OPERATOR <= (
  FUNCTION=eql_v3.ore_block_u64_8_256_lte,
  LEFTARG=eql_v3.ore_block_u64_8_256,
  RIGHTARG=eql_v3.ore_block_u64_8_256,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief >= operator for ORE block types
CREATE OPERATOR >= (
  FUNCTION=eql_v3.ore_block_u64_8_256_gte,
  LEFTARG=eql_v3.ore_block_u64_8_256,
  RIGHTARG=eql_v3.ore_block_u64_8_256,
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
--! query so functional hash/btree indexes built on \`eql_v3.eq_term(col)\`
--! (which calls this) engage structurally.
--!
--! @param val jsonb containing encrypted EQL payload
--! @return eql_v3.hmac_256 HMAC-SHA256 hash value, or NULL when \`hm\` is absent
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
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN val ->> 'hm' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;

--! @file v3/sem/bloom_filter/functions.sql
--! @brief Extractor for the eql_v3 Bloom-filter SEM index term.
--!
--! jsonb-only subset of src/bloom_filter/functions.sql. The encrypted-column
--! overloads are intentionally omitted — the eql_v3 scalar domains extract from
--! the jsonb payload directly via a cast to the domain. (Doc comments
--! deliberately avoid naming eql_v2 symbols so the self-containment grep stays
--! clean.)

--! @brief Test whether a jsonb payload carries a Bloom-filter (\`bf\`) term.
--!
--! @param val jsonb The encrypted payload.
--! @return boolean True when the \`bf\` key is present and non-null.
--!
--! @internal Defined for parity with the eql_v3 SEM index-term predicates
--! (\`has_hmac_256\` / \`has_ore_block_u64_8_256\`); it is not currently called by
--! the extractor below, which gates on value-shape inline, nor by the generated
--! domain CHECK, which tests \`bf\` presence via the envelope-key skeleton. Kept
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
--! query so the functional GIN index built on \`eql_v3.match_term(col)\` (which
--! calls this) engages structurally. Mirrors \`eql_v3.hmac_256(jsonb)\`: no RAISE
--! and no pinned \`search_path\`. Returns NULL when \`bf\` is absent or present but
--! not a json array, rather than raising. The \`text_match\` domain CHECK
--! guarantees the \`bf\` *key* is present but not that it is an array, so a
--! non-array \`bf\` (e.g. \`{"bf": null}\`) can reach here even on a typed value;
--! gating on \`jsonb_typeof(...) = 'array'\` returns NULL for that case — and for
--! raw jsonb outside the domain — instead of erroring inside
--! \`jsonb_array_elements\`. NULL, like the HMAC extractor, is the right answer. An
--! empty \`bf\` array yields an empty filter (contains nothing, contained by
--! everything), matching set-containment semantics.
--!
--! @param val jsonb The encrypted payload.
--! @return eql_v3.bloom_filter The \`bf\` array as a smallint[] domain value, or
--!   NULL when \`bf\` is absent or not a json array.
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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int4_ord)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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
END
$$;
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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int2_ord_ore)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int2_ord)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.date_ord_ore)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int8_ord)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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
        AND VALUE ? 'ob'
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
        AND VALUE ? 'ob'
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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.text_ord)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a eql_v3.text_ord
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.text_ord) $$;

--! @brief Operator wrapper for eql_v3.text_ord.
--! @param a jsonb
--! @param b eql_v3.text_ord
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_ord)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord) <> eql_v3.ord_term(b) $$;

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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.text_ord_ore)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.eq(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.eq(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord_ore) = eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord_ore, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a eql_v3.text_ord_ore
--! @param b jsonb
--! @return boolean
CREATE FUNCTION eql_v3.neq(a eql_v3.text_ord_ore, b jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a) <> eql_v3.ord_term(b::eql_v3.text_ord_ore) $$;

--! @brief Operator wrapper for eql_v3.text_ord_ore.
--! @param a jsonb
--! @param b eql_v3.text_ord_ore
--! @return boolean
CREATE FUNCTION eql_v3.neq(a jsonb, b eql_v3.text_ord_ore)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ord_term(a::eql_v3.text_ord_ore) <> eql_v3.ord_term(b) $$;

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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int4_ord_ore)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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

--! @file encrypted_domain/date/date_ord_functions.sql
--! @brief Functions for eql_v3.date_ord.

--! @brief Index extractor for eql_v3.date_ord.
--! @param a eql_v3.date_ord
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.date_ord)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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
--! @return eql_v3.ore_block_u64_8_256
CREATE FUNCTION eql_v3.ord_term(a eql_v3.int8_ord_ore)
RETURNS eql_v3.ore_block_u64_8_256
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT eql_v3.ore_block_u64_8_256(a::jsonb) $$;

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

--! @file v3/sem/ore_block_u64_8_256/operator_class.sql
--! @brief B-tree operator family + default class on eql_v3.ore_block_u64_8_256.
--!
--! Gives the composite type its DEFAULT btree opclass so the recommended
--! functional index \`CREATE INDEX ON t (eql_v3.ord_term(col))\` engages without
--! an explicit opclass annotation (design D4). Excluded from the Supabase build
--! variant by the \`**/*operator_class.sql\` glob.

--! @brief B-tree operator family for ORE block types
CREATE OPERATOR FAMILY eql_v3.ore_block_u64_8_256_operator_family USING btree;

--! @brief B-tree operator class for ORE block encrypted values
--!
--! Supports operators: <, <=, =, >=, >. Uses comparison function
--! compare_ore_block_u64_8_256_terms.
CREATE OPERATOR CLASS eql_v3.ore_block_u64_8_256_operator_class DEFAULT FOR TYPE eql_v3.ore_block_u64_8_256 USING btree FAMILY eql_v3.ore_block_u64_8_256_operator_family  AS
        OPERATOR 1 <,
        OPERATOR 2 <=,
        OPERATOR 3 =,
        OPERATOR 4 >=,
        OPERATOR 5 >,
        FUNCTION 1 eql_v3.compare_ore_block_u64_8_256_terms(a eql_v3.ore_block_u64_8_256, b eql_v3.ore_block_u64_8_256);
`
