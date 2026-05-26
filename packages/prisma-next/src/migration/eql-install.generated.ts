// @generated — DO NOT EDIT.
// Source: scripts/vendor-eql-install.ts
// Bundle pinned version: eql-2.3.1
//
// This file is committed to source control so dev environments and
// offline builds work without network access. Regenerate with
// `pnpm vendor-eql-install` after bumping EQL_VERSION in the script.

export const EQL_INSTALL_VERSION = 'eql-2.3.1' as const;

export const EQL_INSTALL_SQL: string = `--! @file schema.sql
--! @brief EQL v2 schema creation
--!
--! Creates the eql_v2 schema which contains all Encrypt Query Language
--! functions, types, and tables. Drops existing schema if present to
--! support clean reinstallation.
--!
--! @warning DROP SCHEMA CASCADE will remove all objects in the schema
--! @note All EQL objects (functions, types, tables) reside in eql_v2 schema

--! @brief Drop existing EQL v2 schema
--! @warning CASCADE will drop all dependent objects
DROP SCHEMA IF EXISTS eql_v2 CASCADE;

--! @brief Create EQL v2 schema
--! @note All EQL functions and types will be created in this schema
CREATE SCHEMA eql_v2;

--! @brief Composite type for encrypted column data
--!
--! Core type used for all encrypted columns in EQL. Stores encrypted data as JSONB
--! with the following structure:
--! - \`c\`: ciphertext (base64-encoded encrypted value)
--! - \`i\`: index terms (searchable metadata for encrypted searches)
--! - \`k\`: key ID (identifier for encryption key)
--! - \`m\`: metadata (additional encryption metadata)
--!
--! Created in public schema to persist independently of eql_v2 schema lifecycle.
--! Customer data columns use this type, so it must not be dropped if data exists.
--!
--! @note DO NOT DROP this type unless absolutely certain no encrypted data uses it
--! @see eql_v2.ciphertext
--! @see eql_v2.meta_data
--! @see eql_v2.add_column
DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'eql_v2_encrypted') THEN
      CREATE TYPE public.eql_v2_encrypted AS (
        data jsonb
      );
    END IF;
  END
$$;










--! @brief Bloom filter index term type
--!
--! Domain type representing Bloom filter bit arrays stored as smallint arrays.
--! Used for pattern-match encrypted searches via the 'match' index type.
--! The filter is stored in the 'bf' field of encrypted data payloads.
--!
--! @see eql_v2.add_search_config
--! @see eql_v2."~~"
--! @note This is a transient type used only during query execution
CREATE DOMAIN eql_v2.bloom_filter AS smallint[];



--! @brief ORE block term type for Order-Revealing Encryption
--!
--! Composite type representing a single ORE (Order-Revealing Encryption) block term.
--! Stores encrypted data as bytea that enables range comparisons without decryption.
--!
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.compare_ore_block_u64_8_256_term
CREATE TYPE eql_v2.ore_block_u64_8_256_term AS (
  bytes bytea
);


--! @brief ORE block index term type for range queries
--!
--! Composite type containing an array of ORE block terms. Used for encrypted
--! range queries via the 'ore' index type. The array is stored in the 'ob' field
--! of encrypted data payloads.
--!
--! @see eql_v2.add_search_config
--! @see eql_v2.compare_ore_block_u64_8_256_terms
--! @note This is a transient type used only during query execution
CREATE TYPE eql_v2.ore_block_u64_8_256 AS (
  terms eql_v2.ore_block_u64_8_256_term[]
);

--! @brief HMAC-SHA256 index term type
--!
--! Domain type representing HMAC-SHA256 hash values.
--! Used for exact-match encrypted searches via the 'unique' index type.
--! The hash is stored in the 'hm' field of encrypted data payloads.
--!
--! @see eql_v2.add_search_config
--! @note This is a transient type used only during query execution
CREATE DOMAIN eql_v2.hmac_256 AS text;

--! @file src/ste_vec/types.sql
--! @brief Domain type for individual STE-vec entries
--!
--! Defines \`eql_v2.ste_vec_entry\` as a DOMAIN over \`jsonb\` constrained to the
--! shape of a single element inside an \`sv\` array — a JSON object that
--! carries at minimum a selector field (\`s\`). This is the type returned by
--! the \`->\` operator on \`eql_v2_encrypted\` (a single sv element extracted by
--! selector) and the type accepted by sv-element extractors such as
--! \`eql_v2.ore_cllw(eql_v2.ste_vec_entry)\` and
--! \`eql_v2.hmac_256(eql_v2.ste_vec_entry)\`.
--!
--! Why a separate type. Before #219, the \`(eql_v2_encrypted)\` overloads of
--! sv-element extractors read fields like \`oc\` off the root \`data\` jsonb,
--! which is misleading: a root \`EncryptedPayload\` or \`SteVecPayload\` (the
--! shapes that an actual \`eql_v2_encrypted\` column value carries) never has
--! \`oc\` at the root. The previous pattern only worked because the \`->\`
--! operator merged ste-vec entry fields into a fake root-shaped payload
--! before the extractor ran. This domain type makes the distinction
--! explicit: \`eql_v2_encrypted\` is the root shape; \`eql_v2.ste_vec_entry\`
--! is the per-entry shape; extractors are typed accordingly.
--!
--! @note The CHECK constraint reflects the cipherstash-suite emission
--!       contract:
--!         - \`s\` (selector — column-name HMAC) and \`c\` (ciphertext) are
--!           emitted on every sv element.
--!         - Each sv element carries **exactly one** of \`hm\` (HMAC-256, for
--!           hash-equality queries) or \`oc\` (CLLW ORE, for ordered queries)
--!           — they are mutually exclusive. A given selector / field is
--!           configured for one mode or the other; the crypto layer emits
--!           the corresponding term and only that term.
--!       Other fields (\`a\` for array marker, etc.) are allowed but not
--!       required.
--!
--! @see src/operators/->.sql
--! @see src/ore_cllw/functions.sql
--! @see src/hmac_256/functions.sql
CREATE DOMAIN eql_v2.ste_vec_entry AS jsonb
  CHECK (
    jsonb_typeof(VALUE) = 'object'
    AND VALUE ? 's'
    AND VALUE ? 'c'
    AND (VALUE ? 'hm') <> (VALUE ? 'oc')
  );


--! @brief Domain type for an STE-vec containment needle
--!
--! \`eql_v2.stevec_query\` is a query-shaped sv payload: a top-level
--! \`{"sv": [...]}\` object whose elements carry selector + index
--! terms but **never** a ciphertext (\`c\`) field. Containment (\`@>\`)
--! against an \`eql_v2_encrypted\` column is structurally typed
--! through this domain so the call site reads as "match against an
--! sv query", not "compare two encrypted values".
--!
--! Compared to \`eql_v2.ste_vec_entry\` (single sv element with \`s\`,
--! \`c\`, and \`hm\` XOR \`oc\`), \`stevec_query\` is the wrapping
--! \`{"sv": [...]}\` payload: it forbids \`c\` on every element but
--! otherwise keeps the same per-element contract — each element must
--! carry a selector \`s\` and exactly one deterministic term (\`hm\` XOR
--! \`oc\`). This mirrors the \`SteVecQueryElement\` JSON schema and stops
--! selector-only needles (e.g. \`{"sv":[{"s":"x"}]}\`) from casting and
--! then matching every row through the bare \`jsonb @>\` implementation.
--! The implementation of \`ste_vec_contains\` ignores \`c\` either way,
--! but typing the needle as \`stevec_query\` documents the contract at
--! the API surface.
--!
--! @note Constructing a \`stevec_query\` literal from inline JSON works
--!       via the standard DOMAIN cast:
--!         \`'{"sv":[{"s":"<sel>","hm":"<hm>"}]}'::eql_v2.stevec_query\`
--!       Casting an \`eql_v2_encrypted\` value strips \`c\` fields from
--!       each sv element — see \`eql_v2.to_stevec_query\`.
--!
--! @see eql_v2.to_stevec_query
--! @see src/operators/@>.sql
CREATE DOMAIN eql_v2.stevec_query AS jsonb
  CHECK (
    jsonb_typeof(VALUE) = 'object'
    AND VALUE ? 'sv'
    AND jsonb_typeof(VALUE -> 'sv') = 'array'
    -- No element may carry a ciphertext (\`c\`) — this is a query, not a value.
    AND NOT jsonb_path_exists(VALUE, '$.sv[*] ? (exists(@.c))'::jsonpath)
    -- Every element must carry a selector (\`s\`) ...
    AND NOT jsonb_path_exists(VALUE, '$.sv[*] ? (!exists(@.s))'::jsonpath)
    -- ... and exactly one deterministic term — \`hm\` XOR \`oc\` — matching
    -- the \`ste_vec_entry\` emission contract and the \`SteVecQueryElement\`
    -- JSON schema. Rejects selector-only needles that would otherwise
    -- cast and then match every row via the bare \`jsonb @>\` body.
    AND NOT jsonb_path_exists(VALUE, '$.sv[*] ? (exists(@.hm) && exists(@.oc))'::jsonpath)
    AND NOT jsonb_path_exists(VALUE, '$.sv[*] ? (!exists(@.hm) && !exists(@.oc))'::jsonpath)
  );


--! @brief Convert an \`eql_v2_encrypted\` to a \`stevec_query\` needle
--!
--! Normalises each sv element down to the matching-relevant fields:
--! \`s\` (selector) plus exactly one of \`hm\` / \`oc\`. Other fields
--! (\`c\` ciphertext, \`a\` array marker, \`i\`/\`v\` envelope metadata, anything
--! else cipherstash-client might emit) are stripped. This is the
--! canonical needle shape for \`@>\` containment — matching the contract
--! that containment compares by selector + deterministic term and
--! ignores everything else.
--!
--! Designed for use as a functional GIN index expression: a single
--! \`GIN (eql_v2.to_stevec_query(col)::jsonb jsonb_path_ops)\` index
--! covers containment queries against any selector (both hm-bearing
--! and oc-bearing — XOR-aware), and the typed \`@>\` overloads inline
--! to a native \`jsonb @>\` on the same expression so the planner
--! engages Bitmap Index Scan structurally.
--!
--! @param e eql_v2_encrypted Source encrypted payload
--! @return eql_v2.stevec_query Query-shaped needle, sv elements
--!         normalised to \`{s, hm}\` or \`{s, oc}\`.
--!
--! @example
--! -- Functional GIN index — canonical containment recipe
--! CREATE INDEX ON users USING gin (
--!   eql_v2.to_stevec_query(encrypted_doc)::jsonb jsonb_path_ops
--! );
--!
--! -- Cross-row containment
--! SELECT a.*
--!   FROM docs a, docs b
--!  WHERE a.encrypted_doc @> b.encrypted_doc::eql_v2.stevec_query
--!    AND b.id = 42;
--!
--! @see eql_v2.stevec_query
--! @see eql_v2."@>"(eql_v2_encrypted, eql_v2.stevec_query)
CREATE FUNCTION eql_v2.to_stevec_query(e eql_v2_encrypted)
  RETURNS eql_v2.stevec_query
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
       FROM jsonb_array_elements((e).data -> 'sv') AS elem),
      '[]'::jsonb
    )
  )::eql_v2.stevec_query
$$;

CREATE CAST (eql_v2_encrypted AS eql_v2.stevec_query)
  WITH FUNCTION eql_v2.to_stevec_query
  AS ASSIGNMENT;

--! @file crypto.sql
--! @brief PostgreSQL pgcrypto extension enablement
--!
--! Enables the pgcrypto extension which provides cryptographic functions
--! used by EQL for hashing and other cryptographic operations.
--!
--! Installs pgcrypto into the \`extensions\` schema (Supabase convention) to
--! avoid the \`extension_in_public\` lint. Every EQL function that uses
--! pgcrypto has \`pg_catalog, extensions, public\` on its \`search_path\`, so a
--! pre-existing install in \`public\` keeps working — and a pre-existing
--! install anywhere else will be rejected at install time rather than
--! failing later inside an encrypted comparison.
--!
--! @note pgcrypto provides functions like digest(), hmac(), gen_random_bytes()
--! @note If pgcrypto is already installed in \`public\`, EQL works but emits
--!       a NOTICE recommending \`ALTER EXTENSION pgcrypto SET SCHEMA extensions\`.
--! @note If pgcrypto is already installed in any other schema, install
--!       fails. Relocate it first with \`ALTER EXTENSION pgcrypto SET SCHEMA
--!       extensions\` (or move it into \`public\` if compatibility with other
--!       consumers requires it).

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

--! @brief Extract ciphertext from encrypted JSONB value
--!
--! Extracts the ciphertext (c field) from a raw JSONB encrypted value.
--! The ciphertext is the base64-encoded encrypted data.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Text Base64-encoded ciphertext string
--! @throws Exception if 'c' field is not present in JSONB
--!
--! @example
--! -- Extract ciphertext from JSONB literal
--! SELECT eql_v2.ciphertext('{"c":"AQIDBA==","i":{"unique":"..."}}'::jsonb);
--!
--! @see eql_v2.ciphertext(eql_v2_encrypted)
--! @see eql_v2.meta_data
CREATE FUNCTION eql_v2.ciphertext(val jsonb)
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

--! @brief Extract ciphertext from encrypted column value
--!
--! Extracts the ciphertext from an encrypted column value. Convenience
--! overload that unwraps eql_v2_encrypted type and delegates to JSONB version.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return Text Base64-encoded ciphertext string
--! @throws Exception if encrypted value is malformed
--!
--! @example
--! -- Extract ciphertext from encrypted column
--! SELECT eql_v2.ciphertext(encrypted_email) FROM users;
--!
--! @see eql_v2.ciphertext(jsonb)
--! @see eql_v2.meta_data
CREATE FUNCTION eql_v2.ciphertext(val eql_v2_encrypted)
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
  LANGUAGE SQL
AS $$
    SELECT eql_v2.ciphertext(val.data);
$$;

--! @brief State transition function for grouped_value aggregate
--! @internal
--!
--! Returns the first non-null value encountered. Used as state function
--! for the grouped_value aggregate to select first value in each group.
--!
--! @param $1 JSONB Accumulated state (first non-null value found)
--! @param $2 JSONB New value from current row
--! @return JSONB First non-null value (state or new value)
--!
--! @see eql_v2.grouped_value
CREATE FUNCTION eql_v2._first_grouped_value(jsonb, jsonb)
RETURNS jsonb
AS $$
  SELECT COALESCE($1, $2);
$$ LANGUAGE sql IMMUTABLE;

--! @brief Return first non-null encrypted value in a group
--!
--! Aggregate function that returns the first non-null encrypted value
--! encountered within a GROUP BY clause. Useful for deduplication or
--! selecting representative values from grouped encrypted data.
--!
--! @param input JSONB Encrypted values to aggregate
--! @return JSONB First non-null encrypted value in group
--!
--! @example
--! -- Get first email per user group
--! SELECT user_id, eql_v2.grouped_value(encrypted_email)
--! FROM user_emails
--! GROUP BY user_id;
--!
--! -- Deduplicate encrypted values
--! SELECT DISTINCT ON (user_id)
--!   user_id,
--!   eql_v2.grouped_value(encrypted_ssn) as primary_ssn
--! FROM user_records
--! GROUP BY user_id;
--!
--! @see eql_v2._first_grouped_value
CREATE AGGREGATE eql_v2.grouped_value(jsonb) (
  SFUNC = eql_v2._first_grouped_value,
  STYPE = jsonb
);

--! @brief Add validation constraint to encrypted column
--!
--! Adds a CHECK constraint to ensure column values conform to encrypted data
--! structure. Constraint uses eql_v2.check_encrypted to validate format.
--! Called automatically by eql_v2.add_column.
--!
--! @param table_name TEXT Name of table containing the column
--! @param column_name TEXT Name of column to constrain
--! @return Void
--!
--! @example
--! -- Manually add constraint (normally done by add_column)
--! SELECT eql_v2.add_encrypted_constraint('users', 'encrypted_email');
--!
--! -- Resulting constraint:
--! -- ALTER TABLE users ADD CONSTRAINT eql_v2_encrypted_check_encrypted_email
--! --   CHECK (eql_v2.check_encrypted(encrypted_email));
--!
--! @see eql_v2.add_column
--! @see eql_v2.remove_encrypted_constraint
CREATE FUNCTION eql_v2.add_encrypted_constraint(table_name TEXT, column_name TEXT)
  RETURNS void
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    EXECUTE format('ALTER TABLE %I ADD CONSTRAINT eql_v2_encrypted_constraint_%I_%I CHECK (eql_v2.check_encrypted(%I))', table_name, table_name, column_name, column_name);
  EXCEPTION
    WHEN duplicate_table THEN
    WHEN duplicate_object THEN
      RAISE NOTICE 'Constraint \`eql_v2_encrypted_constraint_%_%\` already exists, skipping', table_name, column_name;
  END;
$$ LANGUAGE plpgsql;

--! @brief Remove validation constraint from encrypted column
--!
--! Removes the CHECK constraint that validates encrypted data structure.
--! Called automatically by eql_v2.remove_column. Uses IF EXISTS to avoid
--! errors if constraint doesn't exist.
--!
--! @param table_name TEXT Name of table containing the column
--! @param column_name TEXT Name of column to unconstrain
--! @return Void
--!
--! @example
--! -- Manually remove constraint (normally done by remove_column)
--! SELECT eql_v2.remove_encrypted_constraint('users', 'encrypted_email');
--!
--! @see eql_v2.remove_column
--! @see eql_v2.add_encrypted_constraint
CREATE FUNCTION eql_v2.remove_encrypted_constraint(table_name TEXT, column_name TEXT)
  RETURNS void
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
		EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS eql_v2_encrypted_constraint_%I_%I', table_name, table_name, column_name);
	END;
$$ LANGUAGE plpgsql;

--! @brief Extract metadata from encrypted JSONB value
--!
--! Extracts index terms (i) and version (v) from a raw JSONB encrypted value.
--! Returns metadata object containing searchable index terms without ciphertext.
--!
--! @param jsonb containing encrypted EQL payload
--! @return JSONB Metadata object with 'i' (index terms) and 'v' (version) fields
--!
--! @example
--! -- Extract metadata to inspect index terms
--! SELECT eql_v2.meta_data('{"c":"...","i":{"unique":"abc123"},"v":1}'::jsonb);
--! -- Returns: {"i":{"unique":"abc123"},"v":1}
--!
--! @see eql_v2.meta_data(eql_v2_encrypted)
--! @see eql_v2.ciphertext
CREATE FUNCTION eql_v2.meta_data(val jsonb)
  RETURNS jsonb
  IMMUTABLE STRICT PARALLEL SAFE
  LANGUAGE SQL
AS $$
    SELECT jsonb_build_object('i', val->'i', 'v', val->'v');
$$;

--! @brief Extract metadata from encrypted column value
--!
--! Extracts index terms and version from an encrypted column value.
--! Convenience overload that unwraps eql_v2_encrypted type and
--! delegates to JSONB version.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return JSONB Metadata object with 'i' (index terms) and 'v' (version) fields
--!
--! @example
--! -- Inspect index terms for encrypted column
--! SELECT user_id, eql_v2.meta_data(encrypted_email) as email_metadata
--! FROM users;
--!
--! @see eql_v2.meta_data(jsonb)
--! @see eql_v2.ciphertext
CREATE FUNCTION eql_v2.meta_data(val eql_v2_encrypted)
  RETURNS jsonb
  IMMUTABLE STRICT PARALLEL SAFE
  LANGUAGE SQL
AS $$
    SELECT eql_v2.meta_data(val.data);
$$;

-- AUTOMATICALLY GENERATED FILE

--! @file common.sql
--! @brief Common utility functions
--!
--! Provides general-purpose utility functions used across EQL:
--! - Constant-time bytea comparison for security
--! - JSONB to bytea array conversion
--! - Logging helpers for debugging and testing


--! @brief Constant-time comparison of bytea values
--! @internal
--!
--! Compares two bytea values in constant time to prevent timing attacks.
--! Always checks all bytes even after finding differences, maintaining
--! consistent execution time regardless of where differences occur.
--!
--! @param a bytea First value to compare
--! @param b bytea Second value to compare
--! @return boolean True if values are equal
--!
--! @note Returns false immediately if lengths differ (length is not secret)
--! @note Used for secure comparison of cryptographic values
CREATE FUNCTION eql_v2.bytea_eq(a bytea, b bytea) RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    result boolean;
    differing bytea;
BEGIN

    -- Check if the bytea values are the same length
    IF LENGTH(a) != LENGTH(b) THEN
        RETURN false;
    END IF;

    -- Compare each byte in the bytea values
    result := true;
    FOR i IN 1..LENGTH(a) LOOP
        IF SUBSTRING(a FROM i FOR 1) != SUBSTRING(b FROM i FOR 1) THEN
            result := result AND false;
        END IF;
    END LOOP;

    RETURN result;
END;
$$ LANGUAGE plpgsql;


--! @brief Convert JSONB hex array to bytea array
--! @internal
--!
--! Converts a JSONB array of hex-encoded strings into a PostgreSQL bytea array.
--! Used for deserializing binary data (like ORE terms) from JSONB storage.
--!
--! @param jsonb JSONB array of hex-encoded strings
--! @return bytea[] Array of decoded binary values
--!
--! @note Returns NULL if input is JSON null
--! @note Each array element is hex-decoded to bytea
CREATE FUNCTION eql_v2.jsonb_array_to_bytea_array(val jsonb)
RETURNS bytea[]
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  terms_arr bytea[];
BEGIN
  IF jsonb_typeof(val) = 'null' THEN
    RETURN NULL;
  END IF;

  SELECT array_agg(decode(value::text, 'hex')::bytea)
    INTO terms_arr
  FROM jsonb_array_elements_text(val) AS value;

  RETURN terms_arr;
END;
$$ LANGUAGE plpgsql;


--! @brief Log message for debugging
--!
--! Convenience function to emit log messages during testing and debugging.
--! Uses RAISE NOTICE to output messages to PostgreSQL logs.
--!
--! @param text Message to log
--!
--! @note Primarily used in tests and development
--! @see eql_v2.log(text, text) for contextual logging
CREATE FUNCTION eql_v2.log(s text)
    RETURNS void
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RAISE NOTICE '[LOG] %', s;
END;
$$ LANGUAGE plpgsql;


--! @brief Log message with context
--!
--! Overload of log function that includes context label for better
--! log organization during testing.
--!
--! @param ctx text Context label (e.g., test name, module name)
--! @param s text Message to log
--!
--! @note Format: "[LOG] {ctx} {message}"
--! @see eql_v2.log(text)
CREATE FUNCTION eql_v2.log(ctx text, s text)
    RETURNS void
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RAISE NOTICE '[LOG] % %', ctx, s;
END;
$$ LANGUAGE plpgsql;

--! @brief CLLW ORE index term type for STE-vec range queries
--!
--! Composite type for CLLW (Copyless Logarithmic Width) Order-Revealing
--! Encryption. The ciphertext is stored in the \`oc\` field of encrypted data
--! payloads (Standard-mode \`ste_vec\` elements). Used by \`eql_v2.compare\` and
--! the range operators (\`<\`, \`<=\`, \`>\`, \`>=\`) when the payload carries an
--! \`oc\` term.
--!
--! The wire-format \`oc\` value is a hex string with a leading domain-tag byte
--! (\`0x00\` numeric, \`0x01\` string) followed by the CLLW ciphertext. The
--! decoded \`bytes\` field on this composite carries the full byte string
--! including the tag — the comparator is variable-length capable, so numeric
--! and string values within the same column are ordered correctly: the
--! domain tag separates the two ranges (numeric < string) and the
--! within-domain comparison falls through to the CLLW per-byte protocol.
--!
--! @see eql_v2.add_search_config
--! @see eql_v2.compare_ore_cllw
--! @note This is a transient type used only during query execution
CREATE TYPE eql_v2.ore_cllw AS (
  bytes bytea
);

--! @brief Extract HMAC-SHA256 index term from JSONB payload
--!
--! Extracts the HMAC-SHA256 hash value from the 'hm' field of an encrypted
--! data payload. Inlinable single-statement SQL — the planner can fold this
--! into the calling query so functional hash indexes built on
--! \`eql_v2.hmac_256(col)\` engage structurally.
--!
--! @param jsonb containing encrypted EQL payload
--! @return eql_v2.hmac_256 HMAC-SHA256 hash value, or NULL when \`hm\` is absent
--!
--! @note Returns NULL when the payload lacks \`hm\`. Callers that need to
--!       surface misconfiguration loudly should use
--!       \`eql_v2.hash_encrypted\` (\`GROUP BY\` / \`DISTINCT\` / hash joins)
--!       which raises with a clear message when \`hm\` is missing.
--!
--! @see eql_v2.has_hmac_256
--! @see eql_v2.compare_hmac_256
--! @see eql_v2.hash_encrypted
CREATE FUNCTION eql_v2.hmac_256(val jsonb)
  RETURNS eql_v2.hmac_256
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (val ->> 'hm')::eql_v2.hmac_256
$$;


--! @brief Check if JSONB payload contains HMAC-SHA256 index term
--!
--! Tests whether the encrypted data payload includes an 'hm' field,
--! indicating an HMAC-SHA256 hash is available for exact-match queries.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Boolean True if 'hm' field is present and non-null
--!
--! @see eql_v2.hmac_256
CREATE FUNCTION eql_v2.has_hmac_256(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN val ->> 'hm' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if encrypted column value contains HMAC-SHA256 index term
--!
--! Tests whether an encrypted column value includes an HMAC-SHA256 hash
--! by checking its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return Boolean True if HMAC-SHA256 hash is present
--!
--! @see eql_v2.has_hmac_256(jsonb)
CREATE FUNCTION eql_v2.has_hmac_256(val eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2.has_hmac_256(val.data);
  END;
$$ LANGUAGE plpgsql;



--! @brief Extract HMAC-SHA256 index term from encrypted column value
--!
--! Extracts the HMAC-SHA256 hash from an encrypted column value. Inlinable
--! single-statement SQL — see the jsonb overload for the rationale.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return eql_v2.hmac_256 HMAC-SHA256 hash value, or NULL when \`hm\` is absent
--!
--! @see eql_v2.hmac_256(jsonb)
CREATE FUNCTION eql_v2.hmac_256(val eql_v2_encrypted)
  RETURNS eql_v2.hmac_256
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT ((val).data ->> 'hm')::eql_v2.hmac_256
$$;


--! @brief Extract HMAC-SHA256 index term from a ste_vec entry
--!
--! Extracts the HMAC from the \`hm\` field of an \`sv\` element extracted via
--! the \`->\` operator. Inlinable. The recipe for field-level equality on
--! encrypted JSON is:
--!
--! @example
--! -- Functional hash index
--! CREATE INDEX ON users USING hash (eql_v2.hmac_256(data -> '<selector>'));
--! -- Bare-form predicate matches via the inlined \`=\` on ste_vec_entry
--! SELECT * FROM users WHERE data -> '<selector>' = $1::eql_v2.ste_vec_entry;
--!
--! @param entry eql_v2.ste_vec_entry STE-vec entry (extracted via \`->\`)
--! @return eql_v2.hmac_256 HMAC value, or NULL when \`hm\` is absent
--!
--! @see eql_v2.has_hmac_256
--! @see src/operators/->.sql
CREATE FUNCTION eql_v2.hmac_256(entry eql_v2.ste_vec_entry)
  RETURNS eql_v2.hmac_256
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (entry ->> 'hm')::eql_v2.hmac_256
$$;


--! @brief Check if a ste_vec entry contains an HMAC-SHA256 index term
--!
--! @param entry eql_v2.ste_vec_entry STE-vec entry
--! @return Boolean True if \`hm\` field is present and non-null
CREATE FUNCTION eql_v2.has_hmac_256(entry eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 'hm' IS NOT NULL
$$;




--! @brief Convert JSONB array to ORE block composite type
--! @internal
--!
--! Converts a JSONB array of hex-encoded ORE terms from the CipherStash Proxy
--! payload into the PostgreSQL composite type used for ORE operations.
--!
--! @param val JSONB Array of hex-encoded ORE block terms
--! @return eql_v2.ore_block_u64_8_256 ORE block composite type, or NULL if input is null
--!
--! @see eql_v2.ore_block_u64_8_256(jsonb)
CREATE FUNCTION eql_v2.jsonb_array_to_ore_block_u64_8_256(val jsonb)
RETURNS eql_v2.ore_block_u64_8_256
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  terms eql_v2.ore_block_u64_8_256_term[];
BEGIN
  IF jsonb_typeof(val) = 'null' THEN
    RETURN NULL;
  END IF;

  SELECT array_agg(ROW(b)::eql_v2.ore_block_u64_8_256_term)
  INTO terms
  FROM unnest(eql_v2.jsonb_array_to_bytea_array(val)) AS b;

  RETURN ROW(terms)::eql_v2.ore_block_u64_8_256;
END;
$$ LANGUAGE plpgsql;


--! @brief Extract ORE block index term from JSONB payload
--!
--! Extracts the ORE block array from the 'ob' field of an encrypted
--! data payload. Used internally for range query comparisons.
--!
--! @param jsonb containing encrypted EQL payload
--! @return eql_v2.ore_block_u64_8_256 ORE block index term
--! @throws Exception if 'ob' field is missing when ore index is expected
--!
--! @see eql_v2.has_ore_block_u64_8_256
--! @see eql_v2.compare_ore_block_u64_8_256
CREATE FUNCTION eql_v2.ore_block_u64_8_256(val jsonb)
  RETURNS eql_v2.ore_block_u64_8_256
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF val IS NULL THEN
      RETURN NULL;
    END IF;

    IF eql_v2.has_ore_block_u64_8_256(val) THEN
      RETURN eql_v2.jsonb_array_to_ore_block_u64_8_256(val->'ob');
    END IF;
    RAISE 'Expected an ore index (ob) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract ORE block index term from encrypted column value
--!
--! Extracts the ORE block from an encrypted column value by accessing
--! its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return eql_v2.ore_block_u64_8_256 ORE block index term
--!
--! @see eql_v2.ore_block_u64_8_256(jsonb)
CREATE FUNCTION eql_v2.ore_block_u64_8_256(val eql_v2_encrypted)
  RETURNS eql_v2.ore_block_u64_8_256
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2.ore_block_u64_8_256(val.data);
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if JSONB payload contains ORE block index term
--!
--! Tests whether the encrypted data payload includes an 'ob' field,
--! indicating an ORE block is available for range queries.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Boolean True if 'ob' field is present and non-null
--!
--! @see eql_v2.ore_block_u64_8_256
CREATE FUNCTION eql_v2.has_ore_block_u64_8_256(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN val ->> 'ob' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if encrypted column value contains ORE block index term
--!
--! Tests whether an encrypted column value includes an ORE block
--! by checking its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return Boolean True if ORE block is present
--!
--! @see eql_v2.has_ore_block_u64_8_256(jsonb)
CREATE FUNCTION eql_v2.has_ore_block_u64_8_256(val eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2.has_ore_block_u64_8_256(val.data);
  END;
$$ LANGUAGE plpgsql;



--! @brief Compare two ORE block terms using cryptographic comparison
--! @internal
--!
--! Performs a three-way comparison (returns -1/0/1) of individual ORE block terms
--! using the ORE cryptographic protocol. Compares PRP and PRF blocks to determine
--! ordering without decryption.
--!
--! @param a eql_v2.ore_block_u64_8_256_term First ORE term to compare
--! @param b eql_v2.ore_block_u64_8_256_term Second ORE term to compare
--! @return Integer -1 if a < b, 0 if a = b, 1 if a > b
--! @throws Exception if ciphertexts are different lengths
--!
--! @note Uses AES-ECB encryption for bit comparisons per ORE protocol
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.compare_ore_block_u64_8_256_term(a eql_v2.ore_block_u64_8_256_term, b eql_v2.ore_block_u64_8_256_term)
  RETURNS integer
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
      -- Compare each PRP (byte from the first 8 bytes) and PRF block (8 byte
      -- chunks of the rest of the value).
      -- NOTE:
      -- * Substr is ordinally indexed (hence 1 and not 0, and 9 and not 8).
      -- * We are not worrying about timing attacks here; don't fret about
      --   the OR or !=.
      IF
        substr(a.bytes, 1 + block, 1) != substr(b.bytes, 1 + block, 1)
        OR substr(a.bytes, 9 + left_block_size * block, left_block_size) != substr(b.bytes, 9 + left_block_size * BLOCK, left_block_size)
      THEN
        -- set the first unequal block we find
        IF eq THEN
          unequal_block := block;
        END IF;
        eq = false;
      END IF;
    END LOOP;

    IF eq THEN
      RETURN 0::integer;
    END IF;

    -- Hash key is the IV from the right CT of b
    hash_key := substr(b.bytes, right_offset + 1, 16);

    -- first right block is at right offset + nonce_size (ordinally indexed)
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
--!
--! Recursively compares arrays of ORE block terms element-by-element.
--! Empty arrays are considered less than non-empty arrays. If the first elements
--! are equal, recursively compares remaining elements.
--!
--! @param a eql_v2.ore_block_u64_8_256_term[] First array of ORE terms
--! @param b eql_v2.ore_block_u64_8_256_term[] Second array of ORE terms
--! @return Integer -1 if a < b, 0 if a = b, 1 if a > b, NULL if either array is NULL
--!
--! @note Empty arrays sort before non-empty arrays
--! @see eql_v2.compare_ore_block_u64_8_256_term
CREATE FUNCTION eql_v2.compare_ore_block_u64_8_256_terms(a eql_v2.ore_block_u64_8_256_term[], b eql_v2.ore_block_u64_8_256_term[])
RETURNS integer
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    cmp_result integer;
  BEGIN

    -- NULLs are NULL
    IF a IS NULL OR b IS NULL THEN
      RETURN NULL;
    END IF;

    -- empty a and b
    IF cardinality(a) = 0 AND cardinality(b) = 0 THEN
      RETURN 0;
    END IF;

    -- empty a and some b
    IF (cardinality(a) = 0) AND cardinality(b) > 0 THEN
      RETURN -1;
    END IF;

    -- some a and empty b
    IF cardinality(a) > 0 AND (cardinality(b) = 0) THEN
      RETURN 1;
    END IF;

    cmp_result := eql_v2.compare_ore_block_u64_8_256_term(a[1], b[1]);

    IF cmp_result = 0 THEN
    -- Removes the first element in the array, and calls this fn again to compare the next element/s in the array.
      RETURN eql_v2.compare_ore_block_u64_8_256_terms(a[2:array_length(a,1)], b[2:array_length(b,1)]);
    END IF;

    RETURN cmp_result;
  END
$$ LANGUAGE plpgsql;


--! @brief Compare ORE block composite types
--! @internal
--!
--! Wrapper function that extracts term arrays from ORE block composite types
--! and delegates to the array comparison function.
--!
--! @param a eql_v2.ore_block_u64_8_256 First ORE block
--! @param b eql_v2.ore_block_u64_8_256 Second ORE block
--! @return Integer -1 if a < b, 0 if a = b, 1 if a > b
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms(eql_v2.ore_block_u64_8_256_term[], eql_v2.ore_block_u64_8_256_term[])
CREATE FUNCTION eql_v2.compare_ore_block_u64_8_256_terms(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS integer
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v2.compare_ore_block_u64_8_256_terms(a.terms, b.terms);
  END
$$ LANGUAGE plpgsql;


--! @brief Extract CLLW ORE index term from a ste_vec entry
--!
--! Returns the CLLW ORE ciphertext from the \`oc\` field of an \`sv\` element.
--! \`oc\` is **only ever present on a \`SteVecElement\`** in the v2.3 payload
--! shape — never at the root of an \`eql_v2_encrypted\` column value — so the
--! type signature accepts \`eql_v2.ste_vec_entry\` directly. Callers must
--! extract first: \`eql_v2.ore_cllw(col -> '<selector>')\`.
--!
--! Inlinable single-statement SQL — the planner folds the body into the
--! calling query so the extractor disappears at planning time. Functional
--! btree index match on this extractor requires the \`eql_v2.ore_cllw_ops\`
--! opclass (installed automatically by the main / protect variants; absent
--! in the supabase variant).
--!
--! **Missing-\`oc\` semantics**: when the \`oc\` field is absent, returns a
--! SQL-level NULL (not a composite with NULL bytes). Btree's standard
--! NULL handling then filters those rows from range queries: they don't
--! match \`WHERE ore_cllw(col) <op> $1\`, they sort at the NULLS LAST end
--! of \`ORDER BY ore_cllw(col)\`, and they never reach the comparator.
--! This avoids the btree FUNCTION 1 contract violation that
--! \`(bytes => NULL)\` would otherwise cause (\`compare_ore_cllw_term\`
--! must return non-NULL int for non-NULL composite inputs).
--!
--! Callers needing a loud RAISE on missing \`oc\` should check
--! \`eql_v2.has_ore_cllw(entry)\` first.
--!
--! @param entry eql_v2.ste_vec_entry STE-vec entry (extracted via \`->\`)
--! @return eql_v2.ore_cllw Composite carrying the CLLW ciphertext, or
--!         NULL when the \`oc\` field is absent.
--!
--! @see eql_v2.has_ore_cllw
--! @see eql_v2.compare_ore_cllw_term
--! @see src/operators/->.sql
CREATE FUNCTION eql_v2.ore_cllw(entry eql_v2.ste_vec_entry)
  RETURNS eql_v2.ore_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE WHEN entry ->> 'oc' IS NULL THEN NULL
              ELSE ROW(decode(entry ->> 'oc', 'hex'))::eql_v2.ore_cllw
         END
$$;


--! @brief Extract CLLW ORE index term from raw jsonb (RHS parameter helper)
--!
--! Companion overload for \`eql_v2.ore_cllw(eql_v2.ste_vec_entry)\` that
--! accepts a raw \`jsonb\` value. Intended for the right-hand side of
--! comparisons where the caller binds a literal/parameter jsonb representing
--! a single ste_vec entry: \`... < eql_v2.ore_cllw($1::jsonb)\`. The (jsonb)
--! form skips the domain CHECK constraint so it works for ad-hoc test inputs
--! and for the GenericComparison case in \`eql_v2.compare_ore_cllw_term\`.
--!
--! Returns SQL-level NULL when the input lacks \`oc\`, matching the
--! \`(ste_vec_entry)\` overload's missing-\`oc\` semantics so a \`WHERE
--! ore_cllw(col) < ore_cllw($1::jsonb)\` with a malformed query needle
--! evaluates to no rows rather than indexing a NULL-bytes composite.
--!
--! @param val jsonb An object carrying an \`oc\` field
--! @return eql_v2.ore_cllw Composite carrying the CLLW ciphertext, or
--!         NULL when the \`oc\` field is absent.
CREATE FUNCTION eql_v2.ore_cllw(val jsonb)
  RETURNS eql_v2.ore_cllw
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE WHEN val ->> 'oc' IS NULL THEN NULL
              ELSE ROW(decode(val ->> 'oc', 'hex'))::eql_v2.ore_cllw
         END
$$;


--! @brief Check if a ste_vec entry contains a CLLW ORE index term
--!
--! Tests whether the entry includes an \`oc\` field. Inlinable.
--!
--! @param entry eql_v2.ste_vec_entry STE-vec entry
--! @return Boolean True if \`oc\` field is present and non-null
--!
--! @see eql_v2.ore_cllw
CREATE FUNCTION eql_v2.has_ore_cllw(entry eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 'oc' IS NOT NULL
$$;


--! @brief Check if a raw jsonb value contains a CLLW ORE index term
--!
--! Companion to \`eql_v2.has_ore_cllw(ste_vec_entry)\` for raw jsonb inputs.
--!
--! @param val jsonb An object that may carry an \`oc\` field
--! @return Boolean True if \`oc\` field is present and non-null
CREATE FUNCTION eql_v2.has_ore_cllw(val jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT val ->> 'oc' IS NOT NULL
$$;


--! @brief CLLW per-byte comparison helper
--! @internal
--!
--! Byte-by-byte comparison implementing the CLLW order-revealing protocol.
--! Used by \`eql_v2.compare_ore_cllw_term\` for the within-prefix step. The
--! protocol: identify the index of the first differing byte across both
--! inputs; if \`(y_byte + 1) == x_byte\` modulo 256 at that index, then x > y;
--! otherwise x < y. Equal inputs return 0.
--!
--! Inputs MUST be the same length. The caller (\`compare_ore_cllw_term\`)
--! guarantees this by passing equal-length prefixes.
--!
--! @par Soft constant-time intent
--! Plpgsql is not a constant-time environment — the interpreter, \`SUBSTRING\`,
--! \`get_byte\`, and the SQL bytea representation all leak timing in ways we
--! can't control from here. Still, the loop deliberately walks every byte
--! (no \`EXIT\` on first difference) and the rotation check uses a bitmask
--! (\`& 255\`) instead of \`% 256\` so that what little timing structure plpgsql
--! does expose is independent of the position and value of the differing
--! byte. This is hardening intent, not a guarantee.
--!
--! Stays \`LANGUAGE plpgsql\` — the per-byte loop can't be expressed as a
--! single inlinable SQL expression. This is the architectural reason ORE
--! CLLW needs a custom operator class for index match, where OPE does not.
--!
--! @param a Bytea First CLLW ciphertext slice
--! @param b Bytea Second CLLW ciphertext slice
--! @return Integer -1, 0, or 1
--! @throws Exception if inputs are different lengths
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.compare_ore_cllw_term_bytes(a bytea, b bytea)
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

    -- Walk every byte, even after a difference is found. Record only the
    -- index of the first difference (1-based; 0 means "no difference").
    -- Avoids an early \`EXIT\` whose presence is itself a timing signal.
    FOR i IN 1..len_a LOOP
        IF first_diff = 0 AND get_byte(a, i - 1) != get_byte(b, i - 1) THEN
            first_diff := i;
        END IF;
    END LOOP;

    IF first_diff = 0 THEN
        RETURN 0;
    END IF;

    -- Bitmask instead of \`% 256\` — the modulo's operand is a power of two
    -- so the two are arithmetically equivalent, but \`& 255\` is a single
    -- machine instruction with no division-related timing variance.
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
--! protocol; on equal prefixes, the shorter input sorts first.
--!
--! Handles both numeric (Standard-mode 65-byte CLLW outputs from the u64
--! variant) and string (variable-length CLLW outputs) by virtue of the
--! domain-tag byte being the first byte of \`bytes\`. A numeric/string pair
--! differs at byte 0 (\`0x00\` vs \`0x01\`), which the CLLW rule resolves
--! correctly to numeric < string.
--!
--! Stays \`LANGUAGE plpgsql\` because it dispatches to
--! \`compare_ore_cllw_term_bytes\`, which can't be inlined.
--!
--! @par Null handling — btree FUNCTION 1 contract
--! PostgreSQL's btree filters NULL composites at the row level, so this
--! function should never be called with \`a IS NULL\` or \`b IS NULL\` under
--! normal operation. The leading IS-NULL guard returns NULL defensively
--! to cover edge cases (e.g., a non-index \`ORDER BY\` or \`WHERE\` path
--! that bypasses the opclass).
--!
--! A composite that is non-NULL but whose \`bytes\` field is NULL is a
--! contract violation: btree expects FUNCTION 1 to return a non-NULL
--! integer for non-NULL composite inputs. The extractor overloads of
--! \`eql_v2.ore_cllw\` are designed to return SQL NULL (not \`ROW(NULL)\`)
--! when the source payload lacks \`oc\`, so a NULL-bytes composite should
--! only arise from a hand-crafted literal or a future field addition to
--! the composite type. Raise loudly to surface the bug instead of
--! producing silent misordering downstream.
--!
--! @param a eql_v2.ore_cllw First term
--! @param b eql_v2.ore_cllw Second term
--! @return Integer -1, 0, or 1; NULL if either composite is NULL
--! @throws Exception if either composite has a NULL \`bytes\` field
--!
--! @see eql_v2.compare_ore_cllw_term_bytes
--! @see eql_v2.compare_ore_cllw
CREATE FUNCTION eql_v2.compare_ore_cllw_term(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
RETURNS int
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    len_a INT;
    len_b INT;
    common_len INT;
    cmp_result INT;
BEGIN
    -- Composite-level NULL: btree's null-handling layer filters these at
    -- the row level under normal operation. Returning NULL covers
    -- non-index code paths that might still reach here.
    IF a IS NULL OR b IS NULL THEN
      RETURN NULL;
    END IF;

    -- Non-NULL composite with NULL bytes is a contract violation: btree's
    -- FUNCTION 1 must return non-NULL int for non-NULL composite inputs.
    -- The extractors return SQL NULL (not ROW(NULL)) on missing \`oc\`, so
    -- reaching here means a hand-crafted literal or a regression in the
    -- extractor body. Raise loudly rather than silently misorder.
    IF a.bytes IS NULL OR b.bytes IS NULL THEN
      RAISE EXCEPTION 'eql_v2.compare_ore_cllw_term: composite has NULL bytes field — extractor invariant violated. Check that the index expression uses eql_v2.ore_cllw(...) and not a hand-crafted ROW(NULL).';
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

    cmp_result := eql_v2.compare_ore_cllw_term_bytes(
      SUBSTRING(a.bytes FROM 1 FOR common_len),
      SUBSTRING(b.bytes FROM 1 FOR common_len)
    );

    IF cmp_result = -1 THEN
        RETURN -1;
    ELSIF cmp_result = 1 THEN
        RETURN 1;
    END IF;

    -- Equal prefixes: shorter sorts first
    IF len_a < len_b THEN
        RETURN -1;
    ELSIF len_a > len_b THEN
        RETURN 1;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;



--! @brief Convert JSONB to encrypted type
--!
--! Wraps a JSONB encrypted payload into the eql_v2_encrypted composite type.
--! Used internally for type conversions and operator implementations.
--!
--! @param jsonb JSONB encrypted payload with structure: {"c": "...", "i": {...}, "k": "...", "v": "2"}
--! @return eql_v2_encrypted Encrypted value wrapped in composite type
--!
--! @note This is primarily used for implicit casts in operator expressions
--! @see eql_v2.to_jsonb
CREATE FUNCTION eql_v2.to_encrypted(data jsonb)
    RETURNS public.eql_v2_encrypted
    IMMUTABLE STRICT PARALLEL SAFE
    LANGUAGE SQL
AS $$
    SELECT ROW(data)::public.eql_v2_encrypted;
$$;


--! @brief Implicit cast from JSONB to encrypted type
--!
--! Enables PostgreSQL to automatically convert JSONB values to eql_v2_encrypted
--! in assignment contexts and comparison operations.
--!
--! @see eql_v2.to_encrypted(jsonb)
CREATE CAST (jsonb AS public.eql_v2_encrypted)
	WITH FUNCTION eql_v2.to_encrypted(jsonb) AS ASSIGNMENT;


--! @brief Convert text to encrypted type
--!
--! Parses a text representation of encrypted JSONB payload and wraps it
--! in the eql_v2_encrypted composite type.
--!
--! @param text Text representation of JSONB encrypted payload
--! @return eql_v2_encrypted Encrypted value wrapped in composite type
--!
--! @note Delegates to eql_v2.to_encrypted(jsonb) after parsing text as JSON
--! @see eql_v2.to_encrypted(jsonb)
CREATE FUNCTION eql_v2.to_encrypted(data text)
    RETURNS public.eql_v2_encrypted
    IMMUTABLE STRICT PARALLEL SAFE
    LANGUAGE SQL
AS $$
    SELECT eql_v2.to_encrypted(data::jsonb);
$$;


--! @brief Implicit cast from text to encrypted type
--!
--! Enables PostgreSQL to automatically convert text JSON strings to eql_v2_encrypted
--! in assignment contexts.
--!
--! @see eql_v2.to_encrypted(text)
CREATE CAST (text AS public.eql_v2_encrypted)
	WITH FUNCTION eql_v2.to_encrypted(text) AS ASSIGNMENT;



--! @brief Convert encrypted type to JSONB
--!
--! Extracts the underlying JSONB payload from an eql_v2_encrypted composite type.
--! Useful for debugging or when raw encrypted payload access is needed.
--!
--! @param e eql_v2_encrypted Encrypted value to unwrap
--! @return jsonb Raw JSONB encrypted payload
--!
--! @note Returns the raw encrypted structure including ciphertext and index terms
--! @see eql_v2.to_encrypted(jsonb)
CREATE FUNCTION eql_v2.to_jsonb(e public.eql_v2_encrypted)
    RETURNS jsonb
    IMMUTABLE STRICT PARALLEL SAFE
    LANGUAGE SQL
AS $$
    SELECT e.data;
$$;

--! @brief Implicit cast from encrypted type to JSONB
--!
--! Enables PostgreSQL to automatically extract the JSONB payload from
--! eql_v2_encrypted values in assignment contexts.
--!
--! @see eql_v2.to_jsonb(eql_v2_encrypted)
CREATE CAST (public.eql_v2_encrypted AS jsonb)
	WITH FUNCTION eql_v2.to_jsonb(public.eql_v2_encrypted) AS ASSIGNMENT;





--! @brief Compare two encrypted values using HMAC-SHA256 index terms
--!
--! Performs a three-way comparison (returns -1/0/1) of encrypted values using
--! their HMAC-SHA256 hash index terms. Used internally by the equality operator (=)
--! for exact-match queries without decryption.
--!
--! @param a eql_v2_encrypted First encrypted value to compare
--! @param b eql_v2_encrypted Second encrypted value to compare
--! @return Integer -1 if a < b, 0 if a = b, 1 if a > b
--!
--! @note NULL values are sorted before non-NULL values
--! @note Comparison uses underlying text type ordering of HMAC-SHA256 hashes
--!
--! @see eql_v2.hmac_256
--! @see eql_v2.has_hmac_256
--! @see eql_v2."="
CREATE FUNCTION eql_v2.compare_hmac_256(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    a_term eql_v2.hmac_256;
    b_term eql_v2.hmac_256;
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

    IF eql_v2.has_hmac_256(a) THEN
      a_term = eql_v2.hmac_256(a);
    END IF;

    IF eql_v2.has_hmac_256(b) THEN
      b_term = eql_v2.hmac_256(b);
    END IF;

    IF a_term IS NULL AND b_term IS NULL THEN
      RETURN 0;
    END IF;

    IF a_term IS NULL THEN
      RETURN -1;
    END IF;

    IF b_term IS NULL THEN
      RETURN 1;
    END IF;

    -- Using the underlying text type comparison
    IF a_term = b_term THEN
      RETURN 0;
    END IF;

    IF a_term < b_term THEN
      RETURN -1;
    END IF;

    IF a_term > b_term THEN
      RETURN 1;
    END IF;

  END;
$$ LANGUAGE plpgsql;



--! @file src/operators/compare.sql
--! @brief Three-way ordering on the root \`eql_v2_encrypted\` type
--!
--! Returns \`-1\` / \`0\` / \`1\` for two encrypted column values that carry
--! Block ORE (\`ob\`) terms at the root. Used by the btree operator class on
--! \`eql_v2_encrypted\` (FUNCTION 1), by the legacy \`eql_v2.lt\` / \`lte\` /
--! \`gt\` / \`gte\` helpers, and by \`sort_compare\`'s \`strategy = 'compare'\`
--! fallback path.
--!
--! **Strict Block-ORE-only contract.** Root-level \`eql_v2_encrypted\` values
--! only carry root-scope ORE terms (\`ob\`) per the v2.3 payload shape — the
--! \`oc\` field (CLLW ORE) is sv-element scope only and never appears on a
--! root payload. Equality on \`eql_v2_encrypted\` is hm-only and runs through
--! the inlined \`=\` / \`<>\` operators (post-#193) — it does *not* go through
--! this function. For sv-element ordering, use the typed
--! \`eql_v2.compare(eql_v2.ste_vec_entry, eql_v2.ste_vec_entry)\` overload
--! (or the \`<\` / \`<=\` / \`>\` / \`>=\` operators on the same pair).
--!
--! @param a eql_v2_encrypted First encrypted value (STRICT — NULL inputs short-circuit to NULL)
--! @param b eql_v2_encrypted Second encrypted value (STRICT — NULL inputs short-circuit to NULL)
--! @return integer -1, 0, or 1
--!
--! @throws Exception when either value lacks an \`ob\` (Block ORE) term
--!
--! @see eql_v2.compare_ore_block_u64_8_256
--! @see eql_v2.compare(eql_v2.ste_vec_entry, eql_v2.ste_vec_entry)
--! @see eql_v2."=" -- hm-only equality, post-#193 inlining
CREATE FUNCTION eql_v2.compare(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF eql_v2.has_ore_block_u64_8_256(a) AND eql_v2.has_ore_block_u64_8_256(b) THEN
      RETURN eql_v2.compare_ore_block_u64_8_256(a, b);
    END IF;

    RAISE EXCEPTION
      'eql_v2.compare requires Block ORE (\`ob\`) on both root operands. For sv-element ordering, extract entries via \`col -> ''<selector>''\` and use eql_v2.compare on the resulting \`eql_v2.ste_vec_entry\` values (or their \`<\` / \`<=\` / \`>\` / \`>=\` operators). Equality is hmac-only via the \`=\` operator — this function is for ordering only.'
      USING ERRCODE = 'feature_not_supported';
  END;
$$ LANGUAGE plpgsql;


--! @brief Three-way ordering on \`eql_v2.ste_vec_entry\`
--!
--! CLLW ORE three-way comparator on ste-vec entries. Returns \`-1\` / \`0\` /
--! \`1\` by extracting the \`oc\` term from each entry and delegating to
--! \`eql_v2.compare_ore_cllw_term\`. Use this when you need an \`int\` ordering
--! out of two extracted ste-vec entries — for the boolean-form operators
--! (\`<\` / \`<=\` / \`>\` / \`>=\`) on the same pair, see
--! \`src/operators/ste_vec_entry.sql\`.
--!
--! Note: the caller is responsible for extracting an \`eql_v2.ste_vec_entry\`
--! first; the \`(eql_v2_encrypted, text)\` form would be a natural extension
--! but is deliberately *not* added here so that callers stay aware of the
--! two-step shape (extract via \`->\`, then compare).
--!
--! @param a eql_v2.ste_vec_entry First entry
--! @param b eql_v2.ste_vec_entry Second entry
--! @return integer -1, 0, or 1
--!
--! @throws Exception when either entry lacks an \`oc\` term
--!
--! @see eql_v2.compare_ore_cllw_term
--! @see src/operators/ste_vec_entry.sql
CREATE FUNCTION eql_v2.compare(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF NOT (eql_v2.has_ore_cllw(a) AND eql_v2.has_ore_cllw(b)) THEN
      RAISE EXCEPTION
        'eql_v2.compare(ste_vec_entry, ste_vec_entry) requires \`oc\` (CLLW ORE) on both entries.'
        USING ERRCODE = 'feature_not_supported';
    END IF;

    RETURN eql_v2.compare_ore_cllw_term(eql_v2.ore_cllw(a), eql_v2.ore_cllw(b));
  END;
$$ LANGUAGE plpgsql;

--! @brief Equality operator for ORE block types
--! @internal
--!
--! Implements the = operator for direct ORE block comparisons.
--!
--! @param a eql_v2.ore_block_u64_8_256 Left operand
--! @param b eql_v2.ore_block_u64_8_256 Right operand
--! @return Boolean True if ORE blocks are equal
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.ore_block_u64_8_256_eq(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_block_u64_8_256_terms(a, b) = 0
$$;



--! @brief Not equal operator for ORE block types
--! @internal
--!
--! Implements the <> operator for direct ORE block comparisons.
--!
--! @param a eql_v2.ore_block_u64_8_256 Left operand
--! @param b eql_v2.ore_block_u64_8_256 Right operand
--! @return Boolean True if ORE blocks are not equal
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.ore_block_u64_8_256_neq(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_block_u64_8_256_terms(a, b) <> 0
$$;



--! @brief Less than operator for ORE block types
--! @internal
--!
--! Implements the < operator for direct ORE block comparisons.
--!
--! @param a eql_v2.ore_block_u64_8_256 Left operand
--! @param b eql_v2.ore_block_u64_8_256 Right operand
--! @return Boolean True if left operand is less than right operand
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.ore_block_u64_8_256_lt(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_block_u64_8_256_terms(a, b) = -1
$$;



--! @brief Less than or equal operator for ORE block types
--! @internal
--!
--! Implements the <= operator for direct ORE block comparisons.
--!
--! @param a eql_v2.ore_block_u64_8_256 Left operand
--! @param b eql_v2.ore_block_u64_8_256 Right operand
--! @return Boolean True if left operand is less than or equal to right operand
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.ore_block_u64_8_256_lte(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_block_u64_8_256_terms(a, b) != 1
$$;



--! @brief Greater than operator for ORE block types
--! @internal
--!
--! Implements the > operator for direct ORE block comparisons.
--!
--! @param a eql_v2.ore_block_u64_8_256 Left operand
--! @param b eql_v2.ore_block_u64_8_256 Right operand
--! @return Boolean True if left operand is greater than right operand
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.ore_block_u64_8_256_gt(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_block_u64_8_256_terms(a, b) = 1
$$;



--! @brief Greater than or equal operator for ORE block types
--! @internal
--!
--! Implements the >= operator for direct ORE block comparisons.
--!
--! @param a eql_v2.ore_block_u64_8_256 Left operand
--! @param b eql_v2.ore_block_u64_8_256 Right operand
--! @return Boolean True if left operand is greater than or equal to right operand
--!
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE FUNCTION eql_v2.ore_block_u64_8_256_gte(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_block_u64_8_256_terms(a, b) != -1
$$;



--! @brief = operator for ORE block types
CREATE OPERATOR = (
  FUNCTION=eql_v2.ore_block_u64_8_256_eq,
  LEFTARG=eql_v2.ore_block_u64_8_256,
  RIGHTARG=eql_v2.ore_block_u64_8_256,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);



--! @brief <> operator for ORE block types
CREATE OPERATOR <> (
  FUNCTION=eql_v2.ore_block_u64_8_256_neq,
  LEFTARG=eql_v2.ore_block_u64_8_256,
  RIGHTARG=eql_v2.ore_block_u64_8_256,
  NEGATOR = =,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);


--! @brief > operator for ORE block types
CREATE OPERATOR > (
  FUNCTION=eql_v2.ore_block_u64_8_256_gt,
  LEFTARG=eql_v2.ore_block_u64_8_256,
  RIGHTARG=eql_v2.ore_block_u64_8_256,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);



--! @brief < operator for ORE block types
CREATE OPERATOR < (
  FUNCTION=eql_v2.ore_block_u64_8_256_lt,
  LEFTARG=eql_v2.ore_block_u64_8_256,
  RIGHTARG=eql_v2.ore_block_u64_8_256,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);



--! @brief <= operator for ORE block types
CREATE OPERATOR <= (
  FUNCTION=eql_v2.ore_block_u64_8_256_lte,
  LEFTARG=eql_v2.ore_block_u64_8_256,
  RIGHTARG=eql_v2.ore_block_u64_8_256,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);



--! @brief >= operator for ORE block types
CREATE OPERATOR >= (
  FUNCTION=eql_v2.ore_block_u64_8_256_gte,
  LEFTARG=eql_v2.ore_block_u64_8_256,
  RIGHTARG=eql_v2.ore_block_u64_8_256,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);


--! @brief Extract STE vector index from JSONB payload
--!
--! Extracts the STE (Searchable Symmetric Encryption) vector from the 'sv' field
--! of an encrypted data payload. Returns an array of encrypted values used for
--! containment queries (@>, <@). If no 'sv' field exists, wraps the entire payload
--! as a single-element array.
--!
--! @param jsonb containing encrypted EQL payload
--! @return eql_v2_encrypted[] Array of encrypted STE vector elements
--!
--! @see eql_v2.ste_vec(eql_v2_encrypted)
--! @see eql_v2.ste_vec_contains
CREATE FUNCTION eql_v2.ste_vec(val jsonb)
  RETURNS public.eql_v2_encrypted[]
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv jsonb;
    ary public.eql_v2_encrypted[];
	BEGIN

    IF val ? 'sv' THEN
      sv := val->'sv';
    ELSE
      sv := jsonb_build_array(val);
    END IF;

    SELECT array_agg(eql_v2.to_encrypted(elem))
      INTO ary
      FROM jsonb_array_elements(sv) AS elem;

    RETURN ary;
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract STE vector index from encrypted column value
--!
--! Extracts the STE vector from an encrypted column value by accessing its
--! underlying JSONB data field. Used for containment query operations.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return eql_v2_encrypted[] Array of encrypted STE vector elements
--!
--! @see eql_v2.ste_vec(jsonb)
CREATE FUNCTION eql_v2.ste_vec(val eql_v2_encrypted)
  RETURNS public.eql_v2_encrypted[]
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN (SELECT eql_v2.ste_vec(val.data));
  END;
$$ LANGUAGE plpgsql;

--! @brief Check if JSONB payload is a single-element STE vector
--!
--! Tests whether the encrypted data payload contains an 'sv' field with exactly
--! one element. Single-element STE vectors can be treated as regular encrypted values.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Boolean True if 'sv' field exists with exactly one element
--!
--! @see eql_v2.to_ste_vec_value
CREATE FUNCTION eql_v2.is_ste_vec_value(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF val ? 'sv' THEN
      RETURN jsonb_array_length(val->'sv') = 1;
    END IF;

    RETURN false;
  END;
$$ LANGUAGE plpgsql;

--! @brief Check if encrypted column value is a single-element STE vector
--!
--! Tests whether an encrypted column value is a single-element STE vector
--! by checking its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return Boolean True if value is a single-element STE vector
--!
--! @see eql_v2.is_ste_vec_value(jsonb)
CREATE FUNCTION eql_v2.is_ste_vec_value(val eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2.is_ste_vec_value(val.data);
  END;
$$ LANGUAGE plpgsql;

--! @brief Convert single-element STE vector to regular encrypted value
--!
--! Extracts the single element from a single-element STE vector and returns it
--! as a regular encrypted value, preserving metadata. If the input is not a
--! single-element STE vector, returns it unchanged.
--!
--! @param jsonb containing encrypted EQL payload
--! @return eql_v2_encrypted Regular encrypted value (unwrapped if single-element STE vector)
--!
--! @see eql_v2.is_ste_vec_value
CREATE FUNCTION eql_v2.to_ste_vec_value(val jsonb)
  RETURNS eql_v2_encrypted
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    meta jsonb;
    sv jsonb;
	BEGIN

    IF val IS NULL THEN
      RETURN NULL;
    END IF;

    IF eql_v2.is_ste_vec_value(val) THEN
      meta := eql_v2.meta_data(val);
      sv := val->'sv';
      sv := sv[0];

      RETURN eql_v2.to_encrypted(meta || sv);
    END IF;

    RETURN eql_v2.to_encrypted(val);
  END;
$$ LANGUAGE plpgsql;

--! @brief Convert single-element STE vector to regular encrypted value (encrypted type)
--!
--! Converts an encrypted column value to a regular encrypted value by unwrapping
--! if it's a single-element STE vector.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return eql_v2_encrypted Regular encrypted value (unwrapped if single-element STE vector)
--!
--! @see eql_v2.to_ste_vec_value(jsonb)
CREATE FUNCTION eql_v2.to_ste_vec_value(val eql_v2_encrypted)
  RETURNS eql_v2_encrypted
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2.to_ste_vec_value(val.data);
  END;
$$ LANGUAGE plpgsql;

--! @brief Extract selector value from JSONB payload
--!
--! Extracts the selector ('s') field from an encrypted data payload.
--! Selectors are used to match STE vector elements during containment queries.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Text The selector value
--! @throws Exception if 's' field is missing
--!
--! @see eql_v2.ste_vec_contains
CREATE FUNCTION eql_v2.selector(val jsonb)
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF val IS NULL THEN
      RETURN NULL;
    END IF;

    IF val ? 's' THEN
      RETURN val->>'s';
    END IF;
    RAISE 'Expected a selector index (s) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract selector value from encrypted column value
--! @internal
--!
--! Internal convenience: unwraps the encrypted composite and delegates
--! to \`eql_v2.selector(jsonb)\`. Exists so the encrypted-selector
--! overloads of \`eql_v2."->"\` / \`eql_v2."->>"\` / \`eql_v2.jsonb_path_*\`
--! can dispatch without each having to spell out \`(val).data\` first.
--! Not part of the public API — callers should use
--! \`eql_v2.selector(jsonb)\` or \`eql_v2.selector(eql_v2.ste_vec_entry)\`.
--!
--! @param eql_v2_encrypted Encrypted column value (single-element form)
--! @return Text The selector value
--!
--! @see eql_v2.selector(jsonb)
--! @see eql_v2.selector(eql_v2.ste_vec_entry)
CREATE FUNCTION eql_v2._selector(val eql_v2_encrypted)
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN (SELECT eql_v2.selector(val.data));
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract selector value from a ste_vec entry
--!
--! Direct overload on the domain type. The DOMAIN's CHECK constraint
--! already guarantees \`s\` is present, so this is a simple field access.
--!
--! @param entry eql_v2.ste_vec_entry STE-vec entry
--! @return Text The selector value
--!
--! @see eql_v2.selector(jsonb)
CREATE FUNCTION eql_v2.selector(entry eql_v2.ste_vec_entry)
  RETURNS text
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT entry ->> 's'
$$;



--! @brief Check if JSONB payload is marked as an STE vector array
--!
--! Tests whether the encrypted data payload has the 'a' (array) flag set to true,
--! indicating it represents an array for STE vector operations.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Boolean True if 'a' field is present and true
--!
--! @see eql_v2.ste_vec
CREATE FUNCTION eql_v2.is_ste_vec_array(val jsonb)
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


--! @brief Check if encrypted column value is marked as an STE vector array
--!
--! Tests whether an encrypted column value has the array flag set by checking
--! its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return Boolean True if value is marked as an STE vector array
--!
--! @see eql_v2.is_ste_vec_array(jsonb)
CREATE FUNCTION eql_v2.is_ste_vec_array(val eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN (SELECT eql_v2.is_ste_vec_array(val.data));
  END;
$$ LANGUAGE plpgsql;



--! @brief Extract full encrypted JSONB elements as array
--!
--! Extracts all JSONB elements from the STE vector including non-deterministic fields.
--! Use jsonb_array() instead for GIN indexing and containment queries.
--!
--! @param val jsonb containing encrypted EQL payload
--! @return jsonb[] Array of full JSONB elements
--!
--! @see eql_v2.jsonb_array
CREATE FUNCTION eql_v2.jsonb_array_from_array_elements(val jsonb)
RETURNS jsonb[]
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT CASE
    WHEN val ? 'sv' THEN
      ARRAY(SELECT elem FROM jsonb_array_elements(val->'sv') AS elem)
    ELSE
      ARRAY[val]
  END;
$$;


--! @brief Extract full encrypted JSONB elements as array from encrypted column
--!
--! @param val eql_v2_encrypted Encrypted column value
--! @return jsonb[] Array of full JSONB elements
--!
--! @see eql_v2.jsonb_array_from_array_elements(jsonb)
CREATE FUNCTION eql_v2.jsonb_array_from_array_elements(val eql_v2_encrypted)
RETURNS jsonb[]
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array_from_array_elements(val.data);
$$;


--! @brief Extract deterministic fields as array for GIN indexing
--!
--! Extracts only deterministic search term fields (\`s\`, \`hm\`, \`oc\`, \`op\`)
--! from each STE vector element. Excludes non-deterministic ciphertext for
--! correct containment comparison using PostgreSQL's native \`@>\` operator.
--!
--! Field set: selector (\`s\`), HMAC equality (\`hm\`), ORE CLLW (\`oc\`,
--! Standard-mode), OPE CLLW (\`op\`, Compat-mode). The pre-2.3 fields
--! (\`b3\` / \`ocf\` / \`ocv\` / \`opf\` / \`opv\`) are no longer emitted — see U-004
--! and U-006 in \`docs/upgrading/v2.3.md\`.
--!
--! @param val jsonb containing encrypted EQL payload
--! @return jsonb[] Array of JSONB elements with only deterministic fields
--!
--! @note Use this for GIN indexes and containment queries
--! @see eql_v2.jsonb_contains
CREATE FUNCTION eql_v2.jsonb_array(val jsonb)
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


--! @brief Extract deterministic fields as array from encrypted column
--!
--! @param val eql_v2_encrypted Encrypted column value
--! @return jsonb[] Array of JSONB elements with only deterministic fields
--!
--! @see eql_v2.jsonb_array(jsonb)
CREATE FUNCTION eql_v2.jsonb_array(val eql_v2_encrypted)
RETURNS jsonb[]
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(val.data);
$$;


--! @brief GIN-indexable JSONB containment check
--!
--! Checks if encrypted value 'a' contains all JSONB elements from 'b'.
--! Uses jsonb[] arrays internally for native PostgreSQL GIN index support.
--!
--! This function is designed for use with a GIN index on jsonb_array(column).
--! When combined with such an index, PostgreSQL can efficiently search large tables.
--!
--! @param a eql_v2_encrypted Container value (typically a table column)
--! @param b eql_v2_encrypted Value to search for
--! @return Boolean True if a contains all elements of b
--!
--! @example
--! -- Create GIN index for efficient containment queries
--! CREATE INDEX idx ON mytable USING GIN (eql_v2.jsonb_array(encrypted_col));
--!
--! -- Query using the helper function
--! SELECT * FROM mytable WHERE eql_v2.jsonb_contains(encrypted_col, search_value);
--!
--! @see eql_v2.jsonb_array
CREATE FUNCTION eql_v2.jsonb_contains(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(a) @> eql_v2.jsonb_array(b);
$$;


--! @brief GIN-indexable JSONB containment check (encrypted, jsonb)
--!
--! Checks if encrypted value 'a' contains all JSONB elements from jsonb value 'b'.
--! Uses jsonb[] arrays internally for native PostgreSQL GIN index support.
--!
--! @param a eql_v2_encrypted Container value (typically a table column)
--! @param b jsonb JSONB value to search for
--! @return Boolean True if a contains all elements of b
--!
--! @see eql_v2.jsonb_array
--! @see eql_v2.jsonb_contains(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.jsonb_contains(a eql_v2_encrypted, b jsonb)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(a) @> eql_v2.jsonb_array(b);
$$;


--! @brief GIN-indexable JSONB containment check (jsonb, encrypted)
--!
--! Checks if jsonb value 'a' contains all JSONB elements from encrypted value 'b'.
--! Uses jsonb[] arrays internally for native PostgreSQL GIN index support.
--!
--! @param a jsonb Container JSONB value
--! @param b eql_v2_encrypted Encrypted value to search for
--! @return Boolean True if a contains all elements of b
--!
--! @see eql_v2.jsonb_array
--! @see eql_v2.jsonb_contains(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.jsonb_contains(a jsonb, b eql_v2_encrypted)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(a) @> eql_v2.jsonb_array(b);
$$;


--! @brief GIN-indexable JSONB "is contained by" check
--!
--! Checks if all JSONB elements from 'a' are contained in 'b'.
--! Uses jsonb[] arrays internally for native PostgreSQL GIN index support.
--!
--! @param a eql_v2_encrypted Value to check (typically a table column)
--! @param b eql_v2_encrypted Container value
--! @return Boolean True if all elements of a are contained in b
--!
--! @see eql_v2.jsonb_array
--! @see eql_v2.jsonb_contains
CREATE FUNCTION eql_v2.jsonb_contained_by(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(a) <@ eql_v2.jsonb_array(b);
$$;


--! @brief GIN-indexable JSONB "is contained by" check (encrypted, jsonb)
--!
--! Checks if all JSONB elements from encrypted value 'a' are contained in jsonb value 'b'.
--! Uses jsonb[] arrays internally for native PostgreSQL GIN index support.
--!
--! @param a eql_v2_encrypted Value to check (typically a table column)
--! @param b jsonb Container JSONB value
--! @return Boolean True if all elements of a are contained in b
--!
--! @see eql_v2.jsonb_array
--! @see eql_v2.jsonb_contained_by(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.jsonb_contained_by(a eql_v2_encrypted, b jsonb)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(a) <@ eql_v2.jsonb_array(b);
$$;


--! @brief GIN-indexable JSONB "is contained by" check (jsonb, encrypted)
--!
--! Checks if all JSONB elements from jsonb value 'a' are contained in encrypted value 'b'.
--! Uses jsonb[] arrays internally for native PostgreSQL GIN index support.
--!
--! @param a jsonb Value to check
--! @param b eql_v2_encrypted Container encrypted value
--! @return Boolean True if all elements of a are contained in b
--!
--! @see eql_v2.jsonb_array
--! @see eql_v2.jsonb_contained_by(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.jsonb_contained_by(a jsonb, b eql_v2_encrypted)
RETURNS boolean
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE SQL
AS $$
  SELECT eql_v2.jsonb_array(a) <@ eql_v2.jsonb_array(b);
$$;


--! @brief Check if STE vector array contains a specific encrypted element
--!
--! Tests whether any element in the STE vector array 'a' contains the encrypted value 'b'.
--! Matching requires both the selector and encrypted value to be equal.
--! Used internally by ste_vec_contains(encrypted, encrypted) for array containment checks.
--!
--! @param eql_v2_encrypted[] STE vector array to search within
--! @param eql_v2_encrypted Encrypted element to search for
--! @return Boolean True if b is found in any element of a
--!
--! @note Compares both selector and encrypted value for match
--!
--! @see eql_v2.selector
--! @see eql_v2.ste_vec_contains(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.ste_vec_contains(a public.eql_v2_encrypted[], b eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    result boolean;
    _a public.eql_v2_encrypted;
  BEGIN

    result := false;

    FOR idx IN 1..array_length(a, 1) LOOP
      _a := a[idx];
      -- Element-level match for ste_vec entries.
      --
      -- Per the v2.3 sv-element contract (encoded in
      -- \`docs/reference/schema/eql-payload-v2.3.schema.json\` and the
      -- \`eql_v2.ste_vec_entry\` DOMAIN), each entry carries **exactly
      -- one** of:
      --   - \`hm\` — HMAC-256 for boolean leaves and for the placeholder
      --     entries that represent array / object roots.
      --   - \`oc\` — CLLW ORE for string and number leaves.
      -- Both terms are deterministic for the same plaintext at the same
      -- selector under the same workspace, so either one serves as the
      -- equality discriminator. A selector configures the leaf's role
      -- (eq / ordered), and the role determines which term is emitted —
      -- two sv entries with the same selector therefore always carry
      -- the same term type.
      --
      -- The selector check is a fast-path gate so we don't compare
      -- terms across mismatched fields. Once selectors match, exactly
      -- one of the two CASE branches fires (XOR contract above).
      --
      -- The \`ELSE false\` arm covers the malformed case (entry carries
      -- neither term, or only one side has the term for a given role).
      -- That's a data error rather than a normal containment result,
      -- but returning false is safer than raising mid-array-scan.
      result := result OR (
        eql_v2._selector(_a) = eql_v2._selector(b) AND
        CASE
          WHEN eql_v2.has_hmac_256(_a) AND eql_v2.has_hmac_256(b) THEN
            eql_v2.compare_hmac_256(_a, b) = 0
          WHEN eql_v2.has_ore_cllw((_a).data) AND eql_v2.has_ore_cllw((b).data) THEN
            eql_v2.compare_ore_cllw_term(
              eql_v2.ore_cllw((_a).data),
              eql_v2.ore_cllw((b).data)
            ) = 0
          ELSE false
        END
      );

      -- Short-circuit once a match is found. Without this we still walk
      -- the rest of the sv array, which on a 100-element document means
      -- 99 wasted selector + extractor calls per row.
      EXIT WHEN result;
    END LOOP;

    RETURN result;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if encrypted value 'a' contains all elements of encrypted value 'b'
--!
--! Performs STE vector containment comparison between two encrypted values.
--! Returns true if all elements in b's STE vector are found in a's STE vector.
--! Used internally by the @> containment operator for searchable encryption.
--!
--! @param a eql_v2_encrypted First encrypted value (container)
--! @param b eql_v2_encrypted Second encrypted value (elements to find)
--! @return Boolean True if all elements of b are contained in a
--!
--! @note Empty b is always contained in any a
--! @note Each element of b must match both selector and value in a
--!
--! @see eql_v2.ste_vec
--! @see eql_v2.ste_vec_contains(eql_v2_encrypted[], eql_v2_encrypted)
--! @see eql_v2."@>"
CREATE FUNCTION eql_v2.ste_vec_contains(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    result boolean;
    sv_a public.eql_v2_encrypted[];
    sv_b public.eql_v2_encrypted[];
    _b public.eql_v2_encrypted;
  BEGIN

    -- jsonb arrays of ste_vec encrypted values
    sv_a := eql_v2.ste_vec(a);
    sv_b := eql_v2.ste_vec(b);

    -- an empty b is always contained in a
    IF array_length(sv_b, 1) IS NULL THEN
      RETURN true;
    END IF;

    IF array_length(sv_a, 1) IS NULL THEN
      RETURN false;
    END IF;

    result := true;

    -- for each element of b check if it is in a
    FOR idx IN 1..array_length(sv_b, 1) LOOP
      _b := sv_b[idx];
      result := result AND eql_v2.ste_vec_contains(sv_a, _b);
    END LOOP;

    RETURN result;
  END;
$$ LANGUAGE plpgsql;
--! @file config/types.sql
--! @brief Configuration state type definition
--!
--! Defines the ENUM type for tracking encryption configuration lifecycle states.
--! The configuration table uses this type to manage transitions between states
--! during setup, activation, and encryption operations.
--!
--! @note CREATE TYPE does not support IF NOT EXISTS, so wrapped in DO block
--! @note Configuration data stored as JSONB directly, not as DOMAIN
--! @see config/tables.sql


--! @brief Configuration lifecycle state
--!
--! Defines valid states for encryption configurations in the eql_v2_configuration table.
--! Configurations transition through these states during setup and activation.
--!
--! @note Only one configuration can be in 'active', 'pending', or 'encrypting' state at once
--! @see config/indexes.sql for uniqueness enforcement
--! @see config/tables.sql for usage in eql_v2_configuration table
DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'eql_v2_configuration_state') THEN
      CREATE TYPE public.eql_v2_configuration_state AS ENUM ('active', 'inactive', 'encrypting', 'pending');
    END IF;
  END
$$;


--! @file src/ore_cllw/operators.sql
--! @brief Comparison operators on the \`eql_v2.ore_cllw\` composite type
--!
--! Same-type comparison operators backing the btree operator class on the
--! composite \`eql_v2.ore_cllw\` type. Each operator reduces to a single SELECT
--! over \`eql_v2.compare_ore_cllw_term(a, b)\`, which is the canonical CLLW
--! per-byte comparator (\`y + 1 == x\` mod 256). The operator wrappers are
--! inlinable \`LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE\` so the planner can
--! fold them into the calling query — that's what lets a functional btree
--! index on \`eql_v2.ore_cllw(col)\` engage for both \`WHERE eql_v2.ore_cllw(col)
--! < eql_v2.ore_cllw($1)\` and \`ORDER BY eql_v2.ore_cllw(col)\` shapes.
--!
--! The inner \`eql_v2.compare_ore_cllw_term\` is \`LANGUAGE plpgsql\` (it has a
--! per-byte loop) and is NOT inlined. That's fine for index *match* (the
--! planner only needs the outer operator function call to fold so the
--! predicate's expression tree matches the index's expression tree); only the
--! per-comparison cost is the plpgsql call overhead. That's the cost the
--! functional index avoids by walking the btree in order rather than calling
--! compare on every row.
--!
--! @note Deliberately no \`HASHES\` / \`MERGES\` flags on the operator
--!       declarations. HASHES requires a registered hash function on the type
--!       (the CLLW protocol gives ordering, not a sensible hashing); MERGES
--!       requires an equivalent merge-joinable operator class on both sides.
--!
--! @see src/ore_cllw/operator_class.sql
--! @see src/ore_cllw/functions.sql

--! @brief Equality operator backing function for \`eql_v2.ore_cllw\`
--! @internal
--!
--! @param a eql_v2.ore_cllw Left operand
--! @param b eql_v2.ore_cllw Right operand
--! @return boolean True if the CLLW terms compare equal
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.ore_cllw_eq(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_cllw_term(a, b) = 0
$$;

--! @brief Inequality operator backing function for \`eql_v2.ore_cllw\`
--! @internal
--!
--! @param a eql_v2.ore_cllw Left operand
--! @param b eql_v2.ore_cllw Right operand
--! @return boolean True if the CLLW terms compare unequal
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.ore_cllw_neq(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_cllw_term(a, b) <> 0
$$;

--! @brief Less-than operator backing function for \`eql_v2.ore_cllw\`
--! @internal
--!
--! @param a eql_v2.ore_cllw Left operand
--! @param b eql_v2.ore_cllw Right operand
--! @return boolean True if \`a\` orders before \`b\`
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.ore_cllw_lt(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_cllw_term(a, b) = -1
$$;

--! @brief Less-than-or-equal operator backing function for \`eql_v2.ore_cllw\`
--! @internal
--!
--! @param a eql_v2.ore_cllw Left operand
--! @param b eql_v2.ore_cllw Right operand
--! @return boolean True if \`a\` orders before or equal to \`b\`
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.ore_cllw_lte(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_cllw_term(a, b) <> 1
$$;

--! @brief Greater-than operator backing function for \`eql_v2.ore_cllw\`
--! @internal
--!
--! @param a eql_v2.ore_cllw Left operand
--! @param b eql_v2.ore_cllw Right operand
--! @return boolean True if \`a\` orders after \`b\`
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.ore_cllw_gt(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_cllw_term(a, b) = 1
$$;

--! @brief Greater-than-or-equal operator backing function for \`eql_v2.ore_cllw\`
--! @internal
--!
--! @param a eql_v2.ore_cllw Left operand
--! @param b eql_v2.ore_cllw Right operand
--! @return boolean True if \`a\` orders after or equal to \`b\`
--!
--! @see eql_v2.compare_ore_cllw_term
CREATE FUNCTION eql_v2.ore_cllw_gte(a eql_v2.ore_cllw, b eql_v2.ore_cllw)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.compare_ore_cllw_term(a, b) <> -1
$$;


CREATE OPERATOR = (
  FUNCTION = eql_v2.ore_cllw_eq,
  LEFTARG = eql_v2.ore_cllw,
  RIGHTARG = eql_v2.ore_cllw,
  COMMUTATOR = =,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel
);

CREATE OPERATOR <> (
  FUNCTION = eql_v2.ore_cllw_neq,
  LEFTARG = eql_v2.ore_cllw,
  RIGHTARG = eql_v2.ore_cllw,
  COMMUTATOR = <>,
  NEGATOR = =,
  RESTRICT = neqsel,
  JOIN = neqjoinsel
);

CREATE OPERATOR < (
  FUNCTION = eql_v2.ore_cllw_lt,
  LEFTARG = eql_v2.ore_cllw,
  RIGHTARG = eql_v2.ore_cllw,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
  FUNCTION = eql_v2.ore_cllw_lte,
  LEFTARG = eql_v2.ore_cllw,
  RIGHTARG = eql_v2.ore_cllw,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

CREATE OPERATOR > (
  FUNCTION = eql_v2.ore_cllw_gt,
  LEFTARG = eql_v2.ore_cllw,
  RIGHTARG = eql_v2.ore_cllw,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
  FUNCTION = eql_v2.ore_cllw_gte,
  LEFTARG = eql_v2.ore_cllw,
  RIGHTARG = eql_v2.ore_cllw,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);


--! @brief Extract Bloom filter index term from JSONB payload
--!
--! Extracts the Bloom filter array from the 'bf' field of an encrypted
--! data payload. Used internally for pattern-match queries (LIKE operator).
--!
--! @param jsonb containing encrypted EQL payload
--! @return eql_v2.bloom_filter Bloom filter as smallint array
--! @throws Exception if 'bf' field is missing when bloom_filter index is expected
--!
--! @see eql_v2.has_bloom_filter
--! @see eql_v2."~~"
CREATE FUNCTION eql_v2.bloom_filter(val jsonb)
  RETURNS eql_v2.bloom_filter
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF val IS NULL THEN
      RETURN NULL;
    END IF;

    IF eql_v2.has_bloom_filter(val) THEN
      RETURN ARRAY(SELECT jsonb_array_elements(val->'bf'))::eql_v2.bloom_filter;
    END IF;

    RAISE 'Expected a match index (bf) value in json: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract Bloom filter index term from encrypted column value
--!
--! Extracts the Bloom filter from an encrypted column value by accessing
--! its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return eql_v2.bloom_filter Bloom filter as smallint array
--!
--! @see eql_v2.bloom_filter(jsonb)
CREATE FUNCTION eql_v2.bloom_filter(val eql_v2_encrypted)
  RETURNS eql_v2.bloom_filter
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN (SELECT eql_v2.bloom_filter(val.data));
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if JSONB payload contains Bloom filter index term
--!
--! Tests whether the encrypted data payload includes a 'bf' field,
--! indicating a Bloom filter is available for pattern-match queries.
--!
--! @param jsonb containing encrypted EQL payload
--! @return Boolean True if 'bf' field is present and non-null
--!
--! @see eql_v2.bloom_filter
CREATE FUNCTION eql_v2.has_bloom_filter(val jsonb)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN val ->> 'bf' IS NOT NULL;
  END;
$$ LANGUAGE plpgsql;


--! @brief Check if encrypted column value contains Bloom filter index term
--!
--! Tests whether an encrypted column value includes a Bloom filter
--! by checking its underlying JSONB data field.
--!
--! @param eql_v2_encrypted Encrypted column value
--! @return Boolean True if Bloom filter is present
--!
--! @see eql_v2.has_bloom_filter(jsonb)
CREATE FUNCTION eql_v2.has_bloom_filter(val eql_v2_encrypted)
  RETURNS boolean
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2.has_bloom_filter(val.data);
  END;
$$ LANGUAGE plpgsql;

--! @file src/ste_vec/eq_term.sql
--! @brief XOR-aware equality term extractor for \`eql_v2.ste_vec_entry\`
--!
--! Returns the bytea representation of whichever deterministic term
--! the sv entry carries — \`hm\` (HMAC-256) for bool leaves / array
--! roots / object roots, or \`oc\` (CLLW ORE) for string / number
--! leaves. The two byte distributions are disjoint by construction
--! (different keys, different protocols), so byte equality on the
--! coalesce is unambiguous: equal terms imply equal plaintexts under
--! the same selector, and unequal terms imply different plaintexts
--! (or different protocols, which can't happen for a single
--! selector).
--!
--! This is the canonical equality extractor used by \`=\` and \`<>\` on
--! \`eql_v2.ste_vec_entry\` — see \`src/operators/ste_vec_entry.sql\`.
--! The recipe for field-level equality on encrypted JSON is:
--!
--! @example
--! -- Functional hash index covers both hm-bearing and oc-bearing selectors
--! CREATE INDEX ON users USING hash (eql_v2.eq_term(data -> '<selector>'));
--! -- Bare-form predicate matches via the inlined \`=\` on ste_vec_entry
--! SELECT * FROM users WHERE data -> '<selector>' = $1::eql_v2.ste_vec_entry;
--!
--! @param entry eql_v2.ste_vec_entry STE-vec entry (extracted via \`->\`)
--! @return bytea Decoded \`hm\` or \`oc\` bytes (NULL if entry is NULL).
--!
--! @note The XOR contract (each sv entry carries exactly one of \`hm\`
--!       or \`oc\` — enforced by the \`ste_vec_entry\` DOMAIN CHECK) means
--!       the coalesce always picks the one present term.
--!
--! @see eql_v2.hmac_256(eql_v2.ste_vec_entry)
--! @see eql_v2.ore_cllw(eql_v2.ste_vec_entry)
--! @see src/operators/ste_vec_entry.sql
CREATE FUNCTION eql_v2.eq_term(entry eql_v2.ste_vec_entry)
  RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT decode(coalesce(entry ->> 'hm', entry ->> 'oc'), 'hex')
$$;

--! @brief Extract ORE index term for ordering encrypted values
--!
--! Helper function that extracts the ore_block_u64_8_256 index term from an encrypted value
--! for use in ORDER BY clauses when comparison operators are not appropriate or available.
--!
--! @param eql_v2_encrypted Encrypted value to extract order term from
--! @return eql_v2.ore_block_u64_8_256 ORE index term for ordering
--!
--! @example
--! -- Order encrypted values without using comparison operators
--! SELECT * FROM users ORDER BY eql_v2.order_by(encrypted_age);
--!
--! @note Requires 'ore' index configuration on the column
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.add_search_config
CREATE FUNCTION eql_v2.order_by(a eql_v2_encrypted)
  RETURNS eql_v2.ore_block_u64_8_256
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v2.ore_block_u64_8_256(a);
  END;
$$ LANGUAGE plpgsql;

--! @brief Fallback literal comparison for encrypted values
--! @internal
--!
--! Compares two encrypted values by their raw JSONB representation when no
--! suitable index terms are available. This ensures consistent ordering required
--! for btree correctness and prevents "lock BufferContent is not held" errors.
--!
--! Used as a last resort fallback in eql_v2.compare() when encrypted values
--! lack matching index terms (hmac_256, ore).
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
--!
--! @note This compares the encrypted payloads directly, not the plaintext values
--! @note Ordering is consistent but not meaningful for range queries
--! @see eql_v2.compare
CREATE FUNCTION eql_v2.compare_literal(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  LANGUAGE SQL
AS $$
    SELECT CASE
        WHEN a.data < b.data THEN -1
        WHEN a.data > b.data THEN 1
        ELSE 0
    END;
$$;


--! @brief Compare two encrypted values using ORE block index terms
--!
--! Performs a three-way comparison (returns -1/0/1) of encrypted values using
--! their ORE block index terms. Used internally by range operators (<, <=, >, >=)
--! for order-revealing comparisons without decryption.
--!
--! @param a eql_v2_encrypted First encrypted value to compare
--! @param b eql_v2_encrypted Second encrypted value to compare
--! @return Integer -1 if a < b, 0 if a = b, 1 if a > b
--!
--! @note NULL values are sorted before non-NULL values
--! @note Uses ORE cryptographic protocol for secure comparisons
--!
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.has_ore_block_u64_8_256
--! @see eql_v2."<"
--! @see eql_v2.">"
CREATE FUNCTION eql_v2.compare_ore_block_u64_8_256(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    a_term eql_v2.ore_block_u64_8_256;
    b_term eql_v2.ore_block_u64_8_256;
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

    IF eql_v2.has_ore_block_u64_8_256(a) THEN
      a_term := eql_v2.ore_block_u64_8_256(a);
    END IF;

    IF eql_v2.has_ore_block_u64_8_256(a) THEN
      b_term := eql_v2.ore_block_u64_8_256(b);
    END IF;

    IF a_term IS NULL AND b_term IS NULL THEN
      RETURN 0;
    END IF;

    IF a_term IS NULL THEN
      RETURN -1;
    END IF;

    IF b_term IS NULL THEN
      RETURN 1;
    END IF;

    RETURN eql_v2.compare_ore_block_u64_8_256_terms(a_term.terms, b_term.terms);
  END;
$$ LANGUAGE plpgsql;


--! @brief Less-than comparison helper for encrypted values
--! @internal
--! @deprecated Slated for removal in EQL 3.0. Use the \`<\` operator instead.
--!
--! Internal helper that delegates to \`eql_v2.compare\` for less-than
--! testing. The \`<\` operator wrappers no longer call this helper — they
--! inline a direct \`ore_block_u64_8_256\` comparison instead (see the
--! inlinable bodies below).
--!
--! @warning Behaviour now diverges from the \`<\` operator: this helper
--!   still walks \`eql_v2.compare\`'s priority list (ore_block → ore_cllw
--!   → hm), whereas \`<\` goes straight to \`ore_block_u64_8_256\` and raises
--!   on missing \`ob\`. Callers relying on the dispatcher fallback should
--!   migrate to the extractor form: \`eql_v2.ore_cllw(col) <
--!   eql_v2.ore_cllw($1::jsonb)\`. See U-005.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return Boolean True if a < b (compare result = -1)
--!
--! @see eql_v2.compare
--! @see eql_v2."<"
CREATE FUNCTION eql_v2.lt(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v2.compare(a, b) = -1;
  END;
$$ LANGUAGE plpgsql;

--! @brief Less-than operator for encrypted values
--!
--! Implements the < operator for comparing two encrypted values via their
--! \`ob\` (ore_block_u64_8_256) ORE term. Enables range queries and sorting
--! without decryption. Requires the column to carry an \`ob\` term (configured
--! via the \`ore\` index in the EQL schema).
--!
--! @param a eql_v2_encrypted Left operand
--! @param b eql_v2_encrypted Right operand
--! @return Boolean True if a is less than b
--!
--! @example
--! -- Range query on encrypted timestamps
--! SELECT * FROM events
--! WHERE encrypted_timestamp < '2024-01-01'::timestamp::text::eql_v2_encrypted;
--!
--! -- Compare encrypted numeric columns
--! SELECT * FROM products WHERE encrypted_price < encrypted_discount_price;
--!
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.add_search_config
-- Inlinable: \`LANGUAGE sql IMMUTABLE\` with a single SELECT body and no
-- \`SET\` clause. The Postgres planner inlines the body into the calling
-- query during planning, so \`WHERE col < val\` reduces to
-- \`WHERE eql_v2.ore_block_u64_8_256(col) < eql_v2.ore_block_u64_8_256(val)\`
-- and matches a functional btree index built on
-- \`eql_v2.ore_block_u64_8_256(col)\` (using the DEFAULT
-- \`eql_v2.ore_block_u64_8_256_operator_class\`). Bare range queries
-- (\`WHERE col < $1\`) engage the functional ORE index on Supabase and any
-- install that doesn't ship \`eql_v2.encrypted_operator_class\`.
--
-- Behaviour change vs the previous dispatcher-based impl: the old
-- \`eql_v2."<"\` walked \`eql_v2.compare\`, which dispatched through
-- ore_block / ore_cllw_u64 / ore_cllw_var / ope. Now \`<\` requires the
-- column to have \`ore_block_u64_8_256\` configured (i.e. carry an \`ob\`
-- field). Calling \`<\` on a column with only \`ore_cllw_*\` or OPE terms
-- now raises from the \`ore_block_u64_8_256(jsonb)\` extractor
-- (\`Expected an ore index (ob) value in json: ...\`) where it
-- previously returned a Boolean. Loud failure surfaces config errors
-- rather than silently producing zero rows — see U-005.
CREATE FUNCTION eql_v2."<"(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) < eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR <(
  FUNCTION=eql_v2."<",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief Less-than operator for encrypted value and JSONB
--!
--! Overload of < operator accepting JSONB on the right side. Reduces to a
--! direct comparison of the \`ob\` ORE term on both sides; the jsonb
--! extractor \`eql_v2.ore_block_u64_8_256(jsonb)\` reads \`b->'ob'\` directly.
--!
--! @param eql_v2_encrypted Left operand (encrypted value)
--! @param b JSONB Right operand
--! @return Boolean True if a < b
--!
--! @example
--! SELECT * FROM events WHERE encrypted_age < '{"ob":[...]}'::jsonb;
--!
--! @see eql_v2."<"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."<"(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) < eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR <(
  FUNCTION=eql_v2."<",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=jsonb,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief Less-than operator for JSONB and encrypted value
--!
--! Overload of < operator accepting JSONB on the left side. Reduces to a
--! direct comparison of the \`ob\` ORE term on both sides.
--!
--! @param a JSONB Left operand
--! @param eql_v2_encrypted Right operand (encrypted value)
--! @return Boolean True if a < b
--!
--! @example
--! SELECT * FROM events WHERE '{"ob":[...]}'::jsonb < encrypted_date;
--!
--! @see eql_v2."<"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."<"(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) < eql_v2.ore_block_u64_8_256(b)
$$;


CREATE OPERATOR <(
  FUNCTION=eql_v2."<",
  LEFTARG=jsonb,
  RIGHTARG=eql_v2_encrypted,
  COMMUTATOR = >,
  NEGATOR = >=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief Less-than-or-equal comparison helper for encrypted values
--! @internal
--! @deprecated Slated for removal in EQL 3.0. Use the \`<=\` operator instead.
--!
--! Internal helper that delegates to \`eql_v2.compare\` for \`<=\` testing.
--! The \`<=\` operator wrappers no longer go through this helper — see the
--! inlinable bodies below.
--!
--! @warning Behaviour now diverges from the \`<=\` operator: this helper
--!   still walks \`eql_v2.compare\`'s priority list, whereas \`<=\` goes
--!   straight to \`ore_block_u64_8_256\` and raises on missing \`ob\`. See
--!   the matching note on \`eql_v2.lt\` and U-005 for migration guidance.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return Boolean True if a <= b (compare result <= 0)
--!
--! @see eql_v2.compare
--! @see eql_v2."<="
CREATE FUNCTION eql_v2.lte(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v2.compare(a, b) <= 0;
  END;
$$ LANGUAGE plpgsql;

--! @brief Less-than-or-equal operator for encrypted values
--!
--! Implements the <= operator for comparing two encrypted values via their
--! \`ob\` (ore_block_u64_8_256) ORE term. Requires the column to carry an
--! \`ob\` term.
--!
--! @param a eql_v2_encrypted Left operand
--! @param b eql_v2_encrypted Right operand
--! @return Boolean True if a <= b
--!
--! @example
--! SELECT * FROM users WHERE encrypted_age <= '18'::int::text::eql_v2_encrypted;
--!
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.add_search_config
-- Inlinable: see \`src/operators/<.sql\` for the rationale.
CREATE FUNCTION eql_v2."<="(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) <= eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR <=(
  FUNCTION = eql_v2."<=",
  LEFTARG = eql_v2_encrypted,
  RIGHTARG = eql_v2_encrypted,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief <= operator for encrypted value and JSONB
--! @see eql_v2."<="(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."<="(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) <= eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR <=(
  FUNCTION = eql_v2."<=",
  LEFTARG = eql_v2_encrypted,
  RIGHTARG = jsonb,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief <= operator for JSONB and encrypted value
--! @see eql_v2."<="(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."<="(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) <= eql_v2.ore_block_u64_8_256(b)
$$;


CREATE OPERATOR <=(
  FUNCTION = eql_v2."<=",
  LEFTARG = jsonb,
  RIGHTARG = eql_v2_encrypted,
  COMMUTATOR = >=,
  NEGATOR = >,
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief Equality helper for encrypted values
--! @internal
--!
--! Inlinable SQL helper mirroring the \`=\` operator's body: reduces to
--! \`hmac_256(a) = hmac_256(b)\`. Kept for callers that invoked the
--! pre-#193 form (\`eql_v2.eq\`); equivalent to using the \`=\` operator
--! directly.
--!
--! Equality on \`eql_v2_encrypted\` is strictly hmac-based (see U-002).
--! Returns NULL when either side lacks an \`hm\` term — matching the
--! \`=\` operator's behaviour.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return Boolean True if hmac terms match
--!
--! @see eql_v2."="
--! @see eql_v2.hmac_256
CREATE FUNCTION eql_v2.eq(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a) = eql_v2.hmac_256(b)
$$;

--! @brief Equality operator for encrypted values
--!
--! Implements the = operator for comparing two encrypted values using their
--! encrypted index terms (hmac_256). Enables WHERE clause comparisons
--! without decryption.
--!
--! @param a eql_v2_encrypted Left operand
--! @param b eql_v2_encrypted Right operand
--! @return Boolean True if encrypted values are equal
--!
--! @example
--! -- Compare encrypted columns
--! SELECT * FROM users WHERE encrypted_email = other_encrypted_email;
--!
--! -- Search using encrypted literal
--! SELECT * FROM users
--! WHERE encrypted_email = '{"c":"...","i":{"unique":"..."}}'::eql_v2_encrypted;
--!
--! @see eql_v2.compare
--! @see eql_v2.add_search_config
-- Inlinable: \`LANGUAGE sql IMMUTABLE\` with a single SELECT body and no
-- \`SET\` clause. The Postgres planner inlines the body into the calling
-- query during planning, so \`WHERE col = val\` reduces to
-- \`WHERE eql_v2.hmac_256(col) = eql_v2.hmac_256(val)\` and matches a
-- functional hash index built on \`eql_v2.hmac_256(col)\`. Bare equality
-- queries (including those issued by PostgREST and ORMs that don't
-- wrap columns themselves) become fast on Supabase and any
-- --exclude-operator-family install.
--
-- Behaviour change vs the previous dispatcher-based impl: the old
-- \`eql_v2.eq\` walked \`eql_v2.compare\`, which fell back to ORE / Blake3 /
-- literal comparison when HMAC wasn't present. Now \`=\` requires the
-- column to have \`equality\` configured (i.e. carry an \`hm\` field).
-- Calling \`=\` on an ORE-only column will return NULL where it
-- previously returned a Boolean. This is intentional — it surfaces
-- config errors loudly. See the predicate/extractor RFC for context.
CREATE FUNCTION eql_v2."="(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a) = eql_v2.hmac_256(b)
$$;

CREATE OPERATOR = (
  FUNCTION=eql_v2."=",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

--! @brief Equality operator for encrypted value and JSONB
--!
--! Overload of = operator accepting JSONB on the right side. Automatically
--! casts JSONB to eql_v2_encrypted for comparison. Useful for comparing
--! against JSONB literals or columns.
--!
--! @param eql_v2_encrypted Left operand (encrypted value)
--! @param b JSONB Right operand (will be cast to eql_v2_encrypted)
--! @return Boolean True if values are equal
--!
--! @example
--! -- Compare encrypted column to JSONB literal
--! SELECT * FROM users
--! WHERE encrypted_email = '{"c":"...","i":{"unique":"..."}}'::jsonb;
--!
--! @see eql_v2."="(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."="(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a) = eql_v2.hmac_256(b::eql_v2_encrypted)
$$;

CREATE OPERATOR = (
  FUNCTION=eql_v2."=",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=jsonb,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

--! @brief Equality operator for JSONB and encrypted value
--!
--! Overload of = operator accepting JSONB on the left side. Automatically
--! casts JSONB to eql_v2_encrypted for comparison. Enables commutative
--! equality comparisons.
--!
--! @param a JSONB Left operand (will be cast to eql_v2_encrypted)
--! @param eql_v2_encrypted Right operand (encrypted value)
--! @return Boolean True if values are equal
--!
--! @example
--! -- Compare JSONB literal to encrypted column
--! SELECT * FROM users
--! WHERE '{"c":"...","i":{"unique":"..."}}'::jsonb = encrypted_email;
--!
--! @see eql_v2."="(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."="(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a::eql_v2_encrypted) = eql_v2.hmac_256(b)
$$;

CREATE OPERATOR = (
  FUNCTION=eql_v2."=",
  LEFTARG=jsonb,
  RIGHTARG=eql_v2_encrypted,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);


--! @brief Greater-than-or-equal comparison helper for encrypted values
--! @internal
--! @deprecated Slated for removal in EQL 3.0. Use the \`>=\` operator instead.
--!
--! Internal helper that delegates to \`eql_v2.compare\` for \`>=\` testing.
--! The \`>=\` operator wrappers no longer go through this helper — see the
--! inlinable bodies below.
--!
--! @warning Behaviour now diverges from the \`>=\` operator: this helper
--!   still walks \`eql_v2.compare\`'s priority list, whereas \`>=\` goes
--!   straight to \`ore_block_u64_8_256\` and raises on missing \`ob\`. See
--!   the matching note on \`eql_v2.lt\` and U-005 for migration guidance.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return Boolean True if a >= b (compare result >= 0)
--!
--! @see eql_v2.compare
--! @see eql_v2.">="
CREATE FUNCTION eql_v2.gte(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v2.compare(a, b) >= 0;
  END;
$$ LANGUAGE plpgsql;

--! @brief Greater-than-or-equal operator for encrypted values
--!
--! Implements the >= operator for comparing two encrypted values via their
--! \`ob\` (ore_block_u64_8_256) ORE term. Requires the column to carry an
--! \`ob\` term.
--!
--! @param a eql_v2_encrypted Left operand
--! @param b eql_v2_encrypted Right operand
--! @return Boolean True if a >= b
--!
--! @example
--! SELECT * FROM users WHERE encrypted_age >= '18'::int::text::eql_v2_encrypted;
--!
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.add_search_config
-- Inlinable: see \`src/operators/<.sql\` for the rationale.
CREATE FUNCTION eql_v2.">="(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) >= eql_v2.ore_block_u64_8_256(b)
$$;


CREATE OPERATOR >=(
  FUNCTION = eql_v2.">=",
  LEFTARG = eql_v2_encrypted,
  RIGHTARG = eql_v2_encrypted,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

--! @brief >= operator for encrypted value and JSONB
--! @param a eql_v2_encrypted Left operand (encrypted value)
--! @param b jsonb Right operand
--! @return Boolean True if a >= b
--! @see eql_v2.">="(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.">="(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) >= eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR >=(
  FUNCTION = eql_v2.">=",
  LEFTARG = eql_v2_encrypted,
  RIGHTARG=jsonb,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

--! @brief >= operator for JSONB and encrypted value
--! @param a jsonb Left operand
--! @param b eql_v2_encrypted Right operand (encrypted value)
--! @return Boolean True if a >= b
--! @see eql_v2.">="(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.">="(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) >= eql_v2.ore_block_u64_8_256(b)
$$;


CREATE OPERATOR >=(
  FUNCTION = eql_v2.">=",
  LEFTARG = jsonb,
  RIGHTARG =eql_v2_encrypted,
  COMMUTATOR = <=,
  NEGATOR = <,
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);

--! @brief Greater-than comparison helper for encrypted values
--! @internal
--! @deprecated Slated for removal in EQL 3.0. Use the \`>\` operator instead.
--!
--! Internal helper that delegates to \`eql_v2.compare\` for greater-than
--! testing. The \`>\` operator wrappers no longer go through this helper —
--! see the inlinable bodies below.
--!
--! @warning Behaviour now diverges from the \`>\` operator: this helper
--!   still walks \`eql_v2.compare\`'s priority list, whereas \`>\` goes
--!   straight to \`ore_block_u64_8_256\` and raises on missing \`ob\`. See
--!   the matching note on \`eql_v2.lt\` and U-005 for migration guidance.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return Boolean True if a > b (compare result = 1)
--!
--! @see eql_v2.compare
--! @see eql_v2.">"
CREATE FUNCTION eql_v2.gt(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN eql_v2.compare(a, b) = 1;
  END;
$$ LANGUAGE plpgsql;

--! @brief Greater-than operator for encrypted values
--!
--! Implements the > operator for comparing two encrypted values via their
--! \`ob\` (ore_block_u64_8_256) ORE term. Enables range queries and sorting
--! without decryption. Requires the column to carry an \`ob\` term.
--!
--! @param a eql_v2_encrypted Left operand
--! @param b eql_v2_encrypted Right operand
--! @return Boolean True if a is greater than b
--!
--! @example
--! SELECT * FROM events
--! WHERE encrypted_value > '100'::int::text::eql_v2_encrypted;
--!
--! @see eql_v2.ore_block_u64_8_256
--! @see eql_v2.add_search_config
-- Inlinable: see \`src/operators/<.sql\` for the rationale. Predicate
-- \`WHERE col > val\` reduces to
-- \`WHERE eql_v2.ore_block_u64_8_256(col) > eql_v2.ore_block_u64_8_256(val)\`
-- and matches a functional ORE index built on the same expression.
-- Breaking impact: columns with only \`ore_cllw_*\` or OPE terms now
-- raise from the \`ore_block_u64_8_256(jsonb)\` extractor
-- (\`Expected an ore index (ob) value in json: ...\`) where they
-- previously fell through \`eql_v2.compare\`. See U-005.
CREATE FUNCTION eql_v2.">"(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) > eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR >(
  FUNCTION=eql_v2.">",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief > operator for encrypted value and JSONB
--! @param a eql_v2_encrypted Left operand (encrypted value)
--! @param b jsonb Right operand
--! @return Boolean True if a > b
--! @see eql_v2.">"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.">"(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) > eql_v2.ore_block_u64_8_256(b)
$$;

CREATE OPERATOR >(
  FUNCTION = eql_v2.">",
  LEFTARG = eql_v2_encrypted,
  RIGHTARG = jsonb,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief > operator for JSONB and encrypted value
--! @param a jsonb Left operand
--! @param b eql_v2_encrypted Right operand (encrypted value)
--! @return Boolean True if a > b
--! @see eql_v2.">"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2.">"(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_block_u64_8_256(a) > eql_v2.ore_block_u64_8_256(b)
$$;


CREATE OPERATOR >(
  FUNCTION = eql_v2.">",
  LEFTARG = jsonb,
  RIGHTARG = eql_v2_encrypted,
  COMMUTATOR = <,
  NEGATOR = <=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief Compute hash integer for encrypted value
--!
--! Produces a 32-bit integer hash suitable for PostgreSQL hash joins, GROUP BY,
--! DISTINCT, and hash aggregate operations. Used by the \`eql_v2_encrypted\` hash
--! operator class (\`FUNCTION 1\`). Inlinable single-statement SQL — the SQL
--! function machinery is much cheaper per row than plpgsql, which matters
--! because HashAggregate / hash-join call this once per input row.
--!
--! Returns \`hashtext\` of the root payload's \`hm\` term. This is the canonical
--! bucket for equality groups, since \`=\` on \`eql_v2_encrypted\` reduces to
--! \`hmac_256(a) = hmac_256(b)\` post-#193.
--!
--! @par Contract
--! Callers using \`GROUP BY\` / \`DISTINCT\` / hash joins on \`eql_v2_encrypted\`
--! MUST configure the column with a \`unique\` index so the crypto layer
--! emits \`hm\` — \`hm\` is assumed present. A missing \`hm\` is a misconfiguration
--! that surfaces upstream via [U-002](docs/upgrading/v2.3.md#u-002-equality-and-hashing-require-hmac).
--!
--! @param val eql_v2_encrypted Encrypted value to hash
--! @return integer 32-bit hash value derived from \`hm\`
--!
--! @note For grouping a value extracted from an encrypted JSON document, use
--!       the field-level recipe directly: \`GROUP BY eql_v2.eq_term(col -> '<selector>')\`
--!       (covers both hm-bearing and oc-bearing selectors via the XOR-aware
--!       extractor — see \`src/ste_vec/eq_term.sql\`). That bypasses
--!       \`hash_encrypted\` entirely.
--!
--! @see eql_v2.hmac_256
--! @see eql_v2.has_hmac_256
--! @see eql_v2.compare
CREATE FUNCTION eql_v2.hash_encrypted(val eql_v2_encrypted)
  RETURNS integer
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT pg_catalog.hashtext(eql_v2.hmac_256(val)::text)
$$;

--! @brief Contains operator for encrypted values (@>)
--!
--! Implements the @> (contains) operator for testing if left encrypted value
--! contains the right encrypted value. Uses ste_vec (secure tree encoding vector)
--! index terms for containment testing without decryption.
--!
--! Primarily used for encrypted array or set containment queries.
--!
--! @param a eql_v2_encrypted Left operand (container)
--! @param b eql_v2_encrypted Right operand (contained value)
--! @return Boolean True if a contains b
--!
--! @example
--! -- Check if encrypted array contains value
--! SELECT * FROM documents
--! WHERE encrypted_tags @> '["security"]'::jsonb::eql_v2_encrypted;
--!
--! @note Requires ste_vec index configuration
--! @see eql_v2.ste_vec_contains
--! @see eql_v2.add_search_config
-- Marked IMMUTABLE STRICT PARALLEL SAFE so the planner inlines the body
-- and a functional GIN index on \`eql_v2.ste_vec(col)\` can match
-- \`WHERE col @> val\`. The previous default-VOLATILE declaration prevented
-- inlining and forced seq scan even on Supabase installs that have the
-- ste_vec functional index in place.
CREATE FUNCTION eql_v2."@>"(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ste_vec_contains(a, b)
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v2."@>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted
);


--! @brief Contains operator (@>) with an \`eql_v2.stevec_query\` needle
--!
--! Type-safe containment for the recommended recipe: the right-hand
--! side is an \`stevec_query\` (sv-shaped payload, no \`c\` fields). The
--! body inlines to a native \`jsonb @>\` over \`eql_v2.to_stevec_query(a)::jsonb\`,
--! so the planner can match a functional GIN index built on the same
--! expression — engaging Bitmap Index Scan for bare-form containment
--! across both \`hm\`-bearing and \`oc\`-bearing selectors with a single
--! index.
--!
--! @param a eql_v2_encrypted Left operand (container)
--! @param b eql_v2.stevec_query Right operand (query payload)
--! @return Boolean True if a contains b
--!
--! @example
--! -- Functional GIN index (covers all selectors, hm and oc):
--! CREATE INDEX ON users USING gin (
--!   eql_v2.to_stevec_query(encrypted_doc)::jsonb jsonb_path_ops
--! );
--! -- Bare-form predicate engages the index:
--! SELECT * FROM users
--! WHERE encrypted_doc @> '{"sv":[{"s":"<sel>","hm":"<hm>"}]}'::eql_v2.stevec_query;
--!
--! @see eql_v2.stevec_query
--! @see eql_v2.to_stevec_query
CREATE FUNCTION eql_v2."@>"(a eql_v2_encrypted, b eql_v2.stevec_query)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  -- Single-expression body so the planner can inline. The haystack
  -- normalisation happens in \`to_stevec_query\`; the needle is trusted
  -- to be clean (sv elements of shape \`{s, hm-or-oc}\` — the documented
  -- stevec_query contract). For untrusted needles, callers should
  -- normalise via the json-shape \`{"sv":[{"s":"<sel>","hm":"<term>"}]}\`.
  SELECT eql_v2.to_stevec_query(a)::jsonb @> b::jsonb
$$;

CREATE OPERATOR @>(
  FUNCTION=eql_v2."@>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2.stevec_query
);


--! @brief Contains operator (@>) with an \`eql_v2.ste_vec_entry\` needle
--!
--! Convenience overload for the common pattern "does this encrypted
--! payload include this specific sv entry?". Wraps the entry into a
--! single-element sv array (stripping \`c\`) and reduces to the same
--! \`to_stevec_query(a)::jsonb @> needle::jsonb\` form as the
--! \`stevec_query\` overload — so it engages the same functional GIN
--! index. Inlinable.
--!
--! @param a eql_v2_encrypted Left operand (container)
--! @param b eql_v2.ste_vec_entry Right operand (single entry)
--! @return Boolean True if a contains an sv entry matching \`b\`
--!
--! @example
--! -- Does this row's encrypted doc contain the same name as this other doc?
--! SELECT a.* FROM docs a, docs b
--!  WHERE a.doc @> (b.doc -> '<name-sel>');
--!
--! @see eql_v2.ste_vec_entry
--! @see eql_v2."@>"(eql_v2_encrypted, eql_v2.stevec_query)
CREATE FUNCTION eql_v2."@>"(a eql_v2_encrypted, b eql_v2.ste_vec_entry)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.to_stevec_query(a)::jsonb
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
  FUNCTION=eql_v2."@>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2.ste_vec_entry
);

--! @file config/tables.sql
--! @brief Encryption configuration storage table
--!
--! Defines the main table for storing EQL v2 encryption configurations.
--! Each row represents a configuration specifying which tables/columns to encrypt
--! and what index types to use. Configurations progress through lifecycle states.
--!
--! @see config/types.sql for state ENUM definition
--! @see config/indexes.sql for state uniqueness constraints
--! @see config/constraints.sql for data validation


--! @brief Encryption configuration table
--!
--! Stores encryption configurations with their state and metadata.
--! The 'data' JSONB column contains the full configuration structure including
--! table/column mappings, index types, and casting rules.
--!
--! @note Only one configuration can be 'active', 'pending', or 'encrypting' at once
--! @note 'id' is auto-generated identity column
--! @note 'state' defaults to 'pending' for new configurations
--! @note 'data' validated by CHECK constraint (see config/constraints.sql)
CREATE TABLE IF NOT EXISTS public.eql_v2_configuration
(
    id bigint GENERATED ALWAYS AS IDENTITY,
    state eql_v2_configuration_state NOT NULL DEFAULT 'pending',
    data jsonb,
    created_at timestamptz not null default current_timestamp,
    PRIMARY KEY(id)
);


--! @brief Initialize default configuration structure
--! @internal
--!
--! Creates a default configuration object if input is NULL. Used internally
--! by public configuration functions to ensure consistent structure.
--!
--! @param config JSONB Existing configuration or NULL
--! @return JSONB Configuration with default structure (version 1, empty tables)
CREATE FUNCTION eql_v2.config_default(config jsonb)
  RETURNS jsonb
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF config IS NULL THEN
      SELECT jsonb_build_object('v', 1, 'tables', jsonb_build_object()) INTO config;
    END IF;
    RETURN config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Add table to configuration if not present
--! @internal
--!
--! Ensures the specified table exists in the configuration structure.
--! Creates empty table entry if needed. Idempotent operation.
--!
--! @param table_name Text Name of table to add
--! @param config JSONB Configuration object
--! @return JSONB Updated configuration with table entry
CREATE FUNCTION eql_v2.config_add_table(table_name text, config jsonb)
  RETURNS jsonb
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    tbl jsonb;
  BEGIN
    IF NOT config #> array['tables'] ? table_name THEN
      SELECT jsonb_insert(config, array['tables', table_name], jsonb_build_object()) INTO config;
    END IF;
    RETURN config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Add column to table configuration if not present
--! @internal
--!
--! Ensures the specified column exists in the table's configuration structure.
--! Creates empty column entry with indexes object if needed. Idempotent operation.
--!
--! @param table_name Text Name of parent table
--! @param column_name Text Name of column to add
--! @param config JSONB Configuration object
--! @return JSONB Updated configuration with column entry
CREATE FUNCTION eql_v2.config_add_column(table_name text, column_name text, config jsonb)
  RETURNS jsonb
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    col jsonb;
  BEGIN
    IF NOT config #> array['tables', table_name] ? column_name THEN
      SELECT jsonb_build_object('indexes', jsonb_build_object()) into col;
      SELECT jsonb_set(config, array['tables', table_name, column_name], col) INTO config;
    END IF;
    RETURN config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Set cast type for column in configuration
--! @internal
--!
--! Updates the cast_as field for a column, specifying the PostgreSQL type
--! that decrypted values should be cast to.
--!
--! @param table_name Text Name of parent table
--! @param column_name Text Name of column
--! @param cast_as Text PostgreSQL type for casting (e.g., 'text', 'int', 'jsonb')
--! @param config JSONB Configuration object
--! @return JSONB Updated configuration with cast_as set
CREATE FUNCTION eql_v2.config_add_cast(table_name text, column_name text, cast_as text, config jsonb)
  RETURNS jsonb
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    SELECT jsonb_set(config, array['tables', table_name, column_name, 'cast_as'], to_jsonb(cast_as)) INTO config;
    RETURN config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Add search index to column configuration
--! @internal
--!
--! Inserts a search index entry (unique, match, ore, ste_vec) with its options
--! into the column's indexes object.
--!
--! @param table_name Text Name of parent table
--! @param column_name Text Name of column
--! @param index_name Text Type of index to add
--! @param opts JSONB Index-specific options
--! @param config JSONB Configuration object
--! @return JSONB Updated configuration with index added
CREATE FUNCTION eql_v2.config_add_index(table_name text, column_name text, index_name text, opts jsonb, config jsonb)
  RETURNS jsonb
  IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    SELECT jsonb_insert(config, array['tables', table_name, column_name, 'indexes', index_name], opts) INTO config;
    RETURN config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Generate default options for match index
--! @internal
--!
--! Returns default configuration for match (LIKE) indexes: k=6, bf=2048,
--! ngram tokenizer with token_length=3, downcase filter, include_original=true.
--!
--! @return JSONB Default match index options
CREATE FUNCTION eql_v2.config_match_default()
  RETURNS jsonb
LANGUAGE sql STRICT PARALLEL SAFE
BEGIN ATOMIC
  SELECT jsonb_build_object(
            'k', 6,
            'bf', 2048,
            'include_original', true,
            'tokenizer', json_build_object('kind', 'ngram', 'token_length', 3),
            'token_filters', json_build_array(json_build_object('kind', 'downcase')));
END;
-- AUTOMATICALLY GENERATED FILE
-- Source is version-template.sql

DROP FUNCTION IF EXISTS eql_v2.version();

--! @file version.sql
--! @brief EQL version reporting
--!
--! This file is auto-generated from version.template during build.
--! The version string placeholder is replaced with the actual release version.

--! @brief Get EQL library version string
--!
--! Returns the version string for the installed EQL library.
--! This value is set at build time from the project version.
--!
--! @return text Version string (e.g., "2.1.0" or "DEV" for development builds)
--!
--! @note Auto-generated during build from version.template
--!
--! @example
--! -- Check installed EQL version
--! SELECT eql_v2.version();
--! -- Returns: '2.1.0'
CREATE FUNCTION eql_v2.version()
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT 'eql-2.3.1';
$$ LANGUAGE SQL;


--! @file src/ore_cllw/operator_class.sql
--! @brief Btree operator class on the \`eql_v2.ore_cllw\` composite type
--!
--! Registers the CLLW per-byte comparison operators as a btree opclass for
--! the \`eql_v2.ore_cllw\` composite type. With \`DEFAULT FOR TYPE\`, a functional
--! btree index on \`eql_v2.ore_cllw(col)\` (or any expression returning the
--! composite) automatically picks up this opclass — no annotation needed at
--! index creation time.
--!
--! Why this matters. After the consolidation in #219, ordered comparison on
--! sv-element values (via \`eql_v2.ore_cllw(value -> '<selector>'::text)\`)
--! has correct semantics through the operator backing functions (each
--! reduces to \`compare_ore_cllw_term <op> 0\`), but PostgreSQL won't engage
--! a functional index for \`ORDER BY ...\` or \`WHERE ... < $1\` unless the
--! type has a registered btree opclass that the planner can structurally
--! match. Without this opclass, \`field_order/*\` queries on sv-element CLLW
--! columns fall back to seq scan + Top-N sort (measured 20s+ on 1M rows).
--! With it, the same queries become Index Scan + LIMIT — milliseconds.
--!
--! FUNCTION 1 is the three-way comparator that btree's internal sort uses
--! (returns -1 / 0 / +1). We point it at \`compare_ore_cllw_term\` directly:
--! that's plpgsql by design (the per-byte CLLW protocol needs iteration),
--! and btree calls it once per index entry pair during build / search —
--! not per-row in the outer query.
--!
--! @note Deliberately no operator family registration beyond the opclass
--!       itself: no cross-type operators on \`eql_v2.ore_cllw\` × \`jsonb\`, no
--!       hash support — see operators.sql for the rationale.
--! @note Excluded from the Supabase build variant (the build glob
--!       \`**/*operator_class.sql\` strips operator classes for Supabase
--!       compatibility).
--!
--! @see src/ore_cllw/operators.sql
--! @see src/ore_cllw/functions.sql

CREATE OPERATOR FAMILY eql_v2.ore_cllw_ops USING btree;

CREATE OPERATOR CLASS eql_v2.ore_cllw_ops
  DEFAULT FOR TYPE eql_v2.ore_cllw
  USING btree FAMILY eql_v2.ore_cllw_ops AS
    OPERATOR 1 <  (eql_v2.ore_cllw, eql_v2.ore_cllw),
    OPERATOR 2 <= (eql_v2.ore_cllw, eql_v2.ore_cllw),
    OPERATOR 3 =  (eql_v2.ore_cllw, eql_v2.ore_cllw),
    OPERATOR 4 >= (eql_v2.ore_cllw, eql_v2.ore_cllw),
    OPERATOR 5 >  (eql_v2.ore_cllw, eql_v2.ore_cllw),
    FUNCTION 1 eql_v2.compare_ore_cllw_term(eql_v2.ore_cllw, eql_v2.ore_cllw);


--! @brief B-tree operator family for ORE block types
--!
--! Defines the operator family for creating B-tree indexes on ORE block types.
--!
--! @see eql_v2.ore_block_u64_8_256_operator_class
CREATE OPERATOR FAMILY eql_v2.ore_block_u64_8_256_operator_family USING btree;

--! @brief B-tree operator class for ORE block encrypted values
--!
--! Defines the operator class required for creating B-tree indexes on columns
--! using the ore_block_u64_8_256 type. Enables range queries and ORDER BY on
--! ORE-encrypted data without decryption.
--!
--! Supports operators: <, <=, =, >=, >
--! Uses comparison function: compare_ore_block_u64_8_256_terms
--!
--!
--! @example
--! -- Would be used like (if enabled):
--! CREATE INDEX ON events USING btree (
--!   (encrypted_timestamp::jsonb->'ob')::eql_v2.ore_block_u64_8_256
--! );
--!
--! @see CREATE OPERATOR CLASS in PostgreSQL documentation
--! @see eql_v2.compare_ore_block_u64_8_256_terms
CREATE OPERATOR CLASS eql_v2.ore_block_u64_8_256_operator_class DEFAULT FOR TYPE eql_v2.ore_block_u64_8_256 USING btree FAMILY eql_v2.ore_block_u64_8_256_operator_family  AS
        OPERATOR 1 <,
        OPERATOR 2 <=,
        OPERATOR 3 =,
        OPERATOR 4 >=,
        OPERATOR 5 >,
        FUNCTION 1 eql_v2.compare_ore_block_u64_8_256_terms(a eql_v2.ore_block_u64_8_256, b eql_v2.ore_block_u64_8_256);

--! @brief Cast text to ORE block term
--! @internal
--!
--! Converts text to bytea and wraps in ore_block_u64_8_256_term type.
--! Used internally for ORE block extraction and manipulation.
--!
--! @param t Text Text value to convert
--! @return eql_v2.ore_block_u64_8_256_term ORE term containing bytea representation
--!
--! @see eql_v2.ore_block_u64_8_256_term
CREATE FUNCTION eql_v2.text_to_ore_block_u64_8_256_term(t text)
  RETURNS eql_v2.ore_block_u64_8_256_term
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
BEGIN ATOMIC
	RETURN t::bytea;
END;

--! @brief Implicit cast from text to ORE block term
--!
--! Defines an implicit cast allowing automatic conversion of text values
--! to ore_block_u64_8_256_term type for ORE operations.
--!
--! @see eql_v2.text_to_ore_block_u64_8_256_term
CREATE CAST (text AS eql_v2.ore_block_u64_8_256_term)
	WITH FUNCTION eql_v2.text_to_ore_block_u64_8_256_term(text) AS IMPLICIT;

--! @brief Pattern matching helper using bloom filters
--! @internal
--!
--! Internal helper for LIKE-style pattern matching on encrypted values.
--! Uses bloom filter index terms to test substring containment without decryption.
--! Requires 'match' index configuration on the column.
--!
--! Marked IMMUTABLE so the planner inlines the body and a functional index on
--! \`eql_v2.bloom_filter(col)\` can match \`WHERE eql_v2.like(col, val)\`.
--!
--! @param a eql_v2_encrypted Haystack (value to search in)
--! @param b eql_v2_encrypted Needle (pattern to search for)
--! @return Boolean True if bloom filter of a contains bloom filter of b
--!
--! @see eql_v2."~~"
--! @see eql_v2.bloom_filter
--! @see eql_v2.add_search_config
CREATE FUNCTION eql_v2.like(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
LANGUAGE SQL
IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.bloom_filter(a) @> eql_v2.bloom_filter(b);
$$;

--! @brief Case-insensitive pattern matching helper
--! @internal
--!
--! Internal helper for ILIKE-style case-insensitive pattern matching.
--! Case sensitivity is controlled by index configuration (token_filters with downcase).
--! This function has same implementation as like() - actual case handling is in index terms.
--!
--! @param a eql_v2_encrypted Haystack (value to search in)
--! @param b eql_v2_encrypted Needle (pattern to search for)
--! @return Boolean True if bloom filter of a contains bloom filter of b
--!
--! @note Case sensitivity depends on match index token_filters configuration
--! @see eql_v2."~~"
--! @see eql_v2.add_search_config
CREATE FUNCTION eql_v2.ilike(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
LANGUAGE SQL
IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.bloom_filter(a) @> eql_v2.bloom_filter(b);
$$;

--! @brief LIKE operator for encrypted values (pattern matching)
--!
--! Implements the ~~ (LIKE) operator for substring/pattern matching on encrypted
--! text using bloom filter index terms. Enables WHERE col LIKE '%pattern%' queries
--! without decryption. Requires 'match' index configuration on the column.
--!
--! Pattern matching uses n-gram tokenization configured in match index. Token length
--! and filters affect matching behavior.
--!
--! @param a eql_v2_encrypted Haystack (encrypted text to search in)
--! @param b eql_v2_encrypted Needle (encrypted pattern to search for)
--! @return Boolean True if a contains b as substring
--!
--! @example
--! -- Search for substring in encrypted email
--! SELECT * FROM users
--! WHERE encrypted_email ~~ '%@example.com%'::text::eql_v2_encrypted;
--!
--! -- Pattern matching on encrypted names
--! SELECT * FROM customers
--! WHERE encrypted_name ~~ 'John%'::text::eql_v2_encrypted;
--!
--! @brief SQL LIKE operator (~~ operator) for encrypted text pattern matching
--!
--! @param a eql_v2_encrypted Left operand (encrypted value)
--! @param b eql_v2_encrypted Right operand (encrypted pattern)
--! @return boolean True if pattern matches
--!
--! @note Requires match index: eql_v2.add_search_config(table, column, 'match')
--! @see eql_v2.like
--! @see eql_v2.add_search_config
-- Inlinable: delegates to \`eql_v2.like\` which is itself an inlinable
-- single-statement SQL function. Two levels of inlining produce
-- \`eql_v2.bloom_filter(a) @> eql_v2.bloom_filter(b)\`, which matches a
-- functional GIN index built on \`eql_v2.bloom_filter(col)\`. PostgREST
-- and ORM \`~~\`/\`~~*\` queries engage the bloom-filter index without
-- the caller wrapping the column themselves.
CREATE FUNCTION eql_v2."~~"(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.like(a, b)
$$;

CREATE OPERATOR ~~(
  FUNCTION=eql_v2."~~",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

--! @brief Case-insensitive LIKE operator (~~*)
--!
--! Implements ~~* (ILIKE) operator for case-insensitive pattern matching.
--! Case handling depends on match index token_filters configuration (use downcase filter).
--! Same implementation as ~~, with case sensitivity controlled by index configuration.
--!
--! @param a eql_v2_encrypted Haystack
--! @param b eql_v2_encrypted Needle
--! @return Boolean True if a contains b (case-insensitive)
--!
--! @note Configure match index with downcase token filter for case-insensitivity
--! @see eql_v2."~~"
CREATE OPERATOR ~~*(
  FUNCTION=eql_v2."~~",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

--! @brief LIKE operator for encrypted value and JSONB
--!
--! Overload of ~~ operator accepting JSONB on the right side. Automatically
--! casts JSONB to eql_v2_encrypted for bloom filter pattern matching.
--!
--! @param eql_v2_encrypted Haystack (encrypted value)
--! @param b JSONB Needle (will be cast to eql_v2_encrypted)
--! @return Boolean True if a contains b as substring
--!
--! @example
--! SELECT * FROM users WHERE encrypted_email ~~ '%gmail%'::jsonb;
--!
--! @see eql_v2."~~"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."~~"(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.like(a, b::eql_v2_encrypted)
$$;


CREATE OPERATOR ~~(
  FUNCTION=eql_v2."~~",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=jsonb,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

CREATE OPERATOR ~~*(
  FUNCTION=eql_v2."~~",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=jsonb,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

--! @brief LIKE operator for JSONB and encrypted value
--!
--! Overload of ~~ operator accepting JSONB on the left side. Automatically
--! casts JSONB to eql_v2_encrypted for bloom filter pattern matching.
--!
--! @param a JSONB Haystack (will be cast to eql_v2_encrypted)
--! @param eql_v2_encrypted Needle (encrypted pattern)
--! @return Boolean True if a contains b as substring
--!
--! @example
--! SELECT * FROM users WHERE 'test@example.com'::jsonb ~~ encrypted_pattern;
--!
--! @see eql_v2."~~"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."~~"(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.like(a::eql_v2_encrypted, b)
$$;


CREATE OPERATOR ~~(
  FUNCTION=eql_v2."~~",
  LEFTARG=jsonb,
  RIGHTARG=eql_v2_encrypted,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

CREATE OPERATOR ~~*(
  FUNCTION=eql_v2."~~",
  LEFTARG=jsonb,
  RIGHTARG=eql_v2_encrypted,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);


-- -----------------------------------------------------------------------------

--! @file src/operators/ste_vec_entry.sql
--! @brief Comparison operators on \`eql_v2.ste_vec_entry\`
--!
--! Equality (\`=\`, \`<>\`) reduces to \`eq_term(a) = eq_term(b)\` — a bytea
--! comparison of \`coalesce(hm, oc)\`. Ordering (\`<\`, \`<=\`, \`>\`, \`>=\`)
--! reduces to \`ore_cllw(a) <op> ore_cllw(b)\`. Each backing function is
--! inlinable single-statement SQL, so the planner can fold the
--! operator body into the calling query — \`WHERE col -> 'sel' = $1\`
--! and \`WHERE col -> 'sel' < $1\` therefore match functional indexes
--! built on \`eql_v2.eq_term(col -> 'sel')\` /
--! \`eql_v2.ore_cllw(col -> 'sel')\` without per-query rewriting.
--!
--! XOR contract. Each sv entry carries exactly one of \`hm\` (bool
--! leaves, array / object roots) or \`oc\` (string / number leaves) —
--! enforced by the \`ste_vec_entry\` DOMAIN CHECK. Equality coalesces
--! across both protocols because both are deterministic and the byte
--! distributions are disjoint; ordering strictly uses \`ore_cllw\`
--! (range on hm-only entries is meaningless and produces silent NULL,
--! which the lint subsystem \`src/lint/lints.sql\` flags as a
--! configuration error).
--!
--! Same convention as the \`eql_v2_encrypted\` operators (#193 / #211): the
--! operator-class function-matching layer is what makes index match work
--! structurally, the backing functions just need to inline cleanly through
--! to the extractor calls.
--!
--! @see eql_v2.eq_term(eql_v2.ste_vec_entry)
--! @see eql_v2.ore_cllw(eql_v2.ste_vec_entry)
--! @see src/operators/=.sql
--! @see src/operators/<.sql

--! @brief Equality backing function for \`eql_v2.ste_vec_entry\`
--! @internal
--! @param a eql_v2.ste_vec_entry Left operand
--! @param b eql_v2.ste_vec_entry Right operand
--! @return boolean True if both entries share the same deterministic
--!         equality term (hm-or-oc, via \`eq_term\`).
CREATE FUNCTION eql_v2.eq(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.eq_term(a) = eql_v2.eq_term(b)
$$;

CREATE OPERATOR = (
  FUNCTION = eql_v2.eq,
  LEFTARG  = eql_v2.ste_vec_entry,
  RIGHTARG = eql_v2.ste_vec_entry,
  COMMUTATOR = =,
  NEGATOR  = <>,
  RESTRICT = eqsel,
  JOIN     = eqjoinsel,
  HASHES,
  MERGES
);


--! @brief Inequality backing function for \`eql_v2.ste_vec_entry\`
--! @internal
--! @param a eql_v2.ste_vec_entry Left operand
--! @param b eql_v2.ste_vec_entry Right operand
--! @return boolean True if the entries' equality terms (hm-or-oc, via
--!         \`eq_term\`) differ.
CREATE FUNCTION eql_v2.neq(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.eq_term(a) <> eql_v2.eq_term(b)
$$;

CREATE OPERATOR <> (
  FUNCTION = eql_v2.neq,
  LEFTARG  = eql_v2.ste_vec_entry,
  RIGHTARG = eql_v2.ste_vec_entry,
  COMMUTATOR = <>,
  NEGATOR  = =,
  RESTRICT = neqsel,
  JOIN     = neqjoinsel
);


--! @brief Less-than backing function for \`eql_v2.ste_vec_entry\`
--! @internal
--! @param a eql_v2.ste_vec_entry Left operand
--! @param b eql_v2.ste_vec_entry Right operand
--! @return boolean True if \`a\`'s CLLW ORE term sorts before \`b\`'s
CREATE FUNCTION eql_v2.lt(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_cllw(a) < eql_v2.ore_cllw(b)
$$;

CREATE OPERATOR < (
  FUNCTION = eql_v2.lt,
  LEFTARG  = eql_v2.ste_vec_entry,
  RIGHTARG = eql_v2.ste_vec_entry,
  COMMUTATOR = >,
  NEGATOR  = >=,
  RESTRICT = scalarltsel,
  JOIN     = scalarltjoinsel
);


--! @brief Less-than-or-equal backing function for \`eql_v2.ste_vec_entry\`
--! @internal
--! @param a eql_v2.ste_vec_entry Left operand
--! @param b eql_v2.ste_vec_entry Right operand
--! @return boolean True if \`a\`'s CLLW ORE term sorts before or equal to \`b\`'s
CREATE FUNCTION eql_v2.lte(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_cllw(a) <= eql_v2.ore_cllw(b)
$$;

CREATE OPERATOR <= (
  FUNCTION = eql_v2.lte,
  LEFTARG  = eql_v2.ste_vec_entry,
  RIGHTARG = eql_v2.ste_vec_entry,
  COMMUTATOR = >=,
  NEGATOR  = >,
  RESTRICT = scalarlesel,
  JOIN     = scalarlejoinsel
);


--! @brief Greater-than backing function for \`eql_v2.ste_vec_entry\`
--! @internal
--! @param a eql_v2.ste_vec_entry Left operand
--! @param b eql_v2.ste_vec_entry Right operand
--! @return boolean True if \`a\`'s CLLW ORE term sorts after \`b\`'s
CREATE FUNCTION eql_v2.gt(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_cllw(a) > eql_v2.ore_cllw(b)
$$;

CREATE OPERATOR > (
  FUNCTION = eql_v2.gt,
  LEFTARG  = eql_v2.ste_vec_entry,
  RIGHTARG = eql_v2.ste_vec_entry,
  COMMUTATOR = <,
  NEGATOR  = <=,
  RESTRICT = scalargtsel,
  JOIN     = scalargtjoinsel
);


--! @brief Greater-than-or-equal backing function for \`eql_v2.ste_vec_entry\`
--! @internal
--! @param a eql_v2.ste_vec_entry Left operand
--! @param b eql_v2.ste_vec_entry Right operand
--! @return boolean True if \`a\`'s CLLW ORE term sorts after or equal to \`b\`'s
CREATE FUNCTION eql_v2.gte(a eql_v2.ste_vec_entry, b eql_v2.ste_vec_entry)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.ore_cllw(a) >= eql_v2.ore_cllw(b)
$$;

CREATE OPERATOR >= (
  FUNCTION = eql_v2.gte,
  LEFTARG  = eql_v2.ste_vec_entry,
  RIGHTARG = eql_v2.ste_vec_entry,
  COMMUTATOR = <=,
  NEGATOR  = <,
  RESTRICT = scalargesel,
  JOIN     = scalargejoinsel
);

--! @file operators/sort.sql
--! @brief Comparison-based sorting functions for encrypted values without operator classes
--!
--! Provides O(n log n) quicksort-based sorting using eql_v2.compare() for environments
--! where btree operator classes are unavailable (e.g., Supabase). This is significantly
--! faster than the O(n^2) correlated subquery workaround.
--!
--! When all input rows share an ORE term (\`ob\`) the sort path pre-extracts the
--! ORE order key once per row and compares those keys directly. Rows lacking
--! an ORE term entirely fall back to \`eql_v2.compare()\` per pair.


--! @internal
--! @brief Compare pre-extracted ORE order keys with encrypted NULL semantics
--!
--! Mirrors eql_v2.compare() for NULL handling, then delegates to the
--! ore_block_u64_8_256 comparator when both keys are present.
--!
--! @param a eql_v2.ore_block_u64_8_256 First order key
--! @param b eql_v2.ore_block_u64_8_256 Second order key
--! @return integer -1 if a < b, 0 if a = b, 1 if a > b
CREATE FUNCTION eql_v2._compare_order_key(
    a eql_v2.ore_block_u64_8_256,
    b eql_v2.ore_block_u64_8_256
)
RETURNS integer
IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
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

    RETURN eql_v2.compare_ore_block_u64_8_256_terms(a, b);
END;
$$ LANGUAGE plpgsql;


--! @internal
--! @brief Compare two elements from aligned arrays using the selected sort strategy
--!
--! @param vals eql_v2_encrypted[] Encrypted values (used when strategy = 'compare')
--! @param ore_keys eql_v2.ore_block_u64_8_256[] Pre-extracted ORE keys (strategy = 'ore')
--! @param left_idx integer Index of the left element
--! @param right_idx integer Index of the right element
--! @param strategy text One of 'ore' or 'compare'
--! @return integer -1 if left < right, 0 if equal, 1 if left > right
CREATE FUNCTION eql_v2._compare_sort_elements(
    vals eql_v2_encrypted[],
    ore_keys eql_v2.ore_block_u64_8_256[],
    left_idx integer,
    right_idx integer,
    strategy text
)
RETURNS integer
IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
    IF strategy = 'ore' THEN
        RETURN eql_v2._compare_order_key(ore_keys[left_idx], ore_keys[right_idx]);
    END IF;

    RETURN eql_v2.compare(vals[left_idx], vals[right_idx]);
END;
$$ LANGUAGE plpgsql;


--! @internal
--! @brief Compare an array element against a captured pivot using the selected strategy
--!
--! @param vals eql_v2_encrypted[] Array of encrypted values
--! @param ore_keys eql_v2.ore_block_u64_8_256[] Array of pre-extracted ORE keys
--! @param idx integer Index of the element to compare
--! @param pivot_val eql_v2_encrypted Pivot encrypted value (strategy = 'compare')
--! @param pivot_ore_key eql_v2.ore_block_u64_8_256 Pivot ORE key (strategy = 'ore')
--! @param strategy text One of 'ore' or 'compare'
--! @return integer -1 if element < pivot, 0 if equal, 1 if element > pivot
CREATE FUNCTION eql_v2._compare_sort_pivot(
    vals eql_v2_encrypted[],
    ore_keys eql_v2.ore_block_u64_8_256[],
    idx integer,
    pivot_val eql_v2_encrypted,
    pivot_ore_key eql_v2.ore_block_u64_8_256,
    strategy text
)
RETURNS integer
IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
    IF strategy = 'ore' THEN
        RETURN eql_v2._compare_order_key(ore_keys[idx], pivot_ore_key);
    END IF;

    RETURN eql_v2.compare(vals[idx], pivot_val);
END;
$$ LANGUAGE plpgsql;


--! @internal
--! @brief In-place insertion sort on parallel id/value/key arrays
--!
--! @param ids bigint[] Array of row identifiers (reordered in place)
--! @param vals eql_v2_encrypted[] Array of encrypted values (reordered in place)
--! @param ore_keys eql_v2.ore_block_u64_8_256[] Array of pre-extracted ORE keys (reordered in place)
--! @param lo integer Lower bound index (1-based, inclusive)
--! @param hi integer Upper bound index (1-based, inclusive)
--! @param strategy text One of 'ore' or 'compare'
--! @return ids bigint[] Sorted array of row identifiers
--! @return vals eql_v2_encrypted[] Sorted array of encrypted values
--! @return ore_keys eql_v2.ore_block_u64_8_256[] Sorted array of pre-extracted ORE keys
CREATE FUNCTION eql_v2._insertion_sort(
    INOUT ids bigint[],
    INOUT vals eql_v2_encrypted[],
    INOUT ore_keys eql_v2.ore_block_u64_8_256[],
    lo integer,
    hi integer,
    strategy text
)
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    i integer;
    j integer;
    key_id bigint;
    key_val eql_v2_encrypted;
    sort_ore_key eql_v2.ore_block_u64_8_256;
BEGIN
    IF lo >= hi THEN
        RETURN;
    END IF;

    FOR i IN lo + 1..hi LOOP
        key_id := ids[i];
        key_val := vals[i];
        sort_ore_key := ore_keys[i];
        j := i - 1;

        WHILE j >= lo LOOP
            EXIT WHEN strategy = 'compare'
                AND eql_v2.compare(vals[j], key_val) <= 0;
            EXIT WHEN strategy = 'ore'
                AND eql_v2._compare_order_key(ore_keys[j], sort_ore_key) <= 0;

            ids[j + 1] := ids[j];
            vals[j + 1] := vals[j];
            ore_keys[j + 1] := ore_keys[j];
            j := j - 1;
        END LOOP;

        ids[j + 1] := key_id;
        vals[j + 1] := key_val;
        ore_keys[j + 1] := sort_ore_key;
    END LOOP;
END;
$$ LANGUAGE plpgsql;


--! @internal
--! @brief In-place quicksort on parallel id/value/key arrays
--!
--! Sorts aligned arrays simultaneously using Hoare partition with median-of-three pivot
--! selection. The median-of-three strategy avoids O(n^2) degradation on already-sorted
--! input, which is common with sequential test data.
--!
--! @param ids bigint[] Array of row identifiers (reordered in place)
--! @param vals eql_v2_encrypted[] Array of encrypted values to compare (reordered in place)
--! @param ore_keys eql_v2.ore_block_u64_8_256[] Pre-extracted ORE keys (reordered in place)
--! @param lo integer Lower bound index (1-based, inclusive)
--! @param hi integer Upper bound index (1-based, inclusive)
--! @param strategy text One of 'ore' or 'compare'
--!
--! @return ids bigint[] Sorted array of row identifiers
--! @return vals eql_v2_encrypted[] Sorted array of encrypted values
--! @return ore_keys eql_v2.ore_block_u64_8_256[] Sorted array of pre-extracted ORE keys
CREATE FUNCTION eql_v2._quicksort_sorter(
    INOUT ids bigint[],
    INOUT vals eql_v2_encrypted[],
    INOUT ore_keys eql_v2.ore_block_u64_8_256[],
    lo integer,
    hi integer,
    strategy text
)
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    insertion_threshold CONSTANT integer := 16;
    pivot_val eql_v2_encrypted;
    pivot_ore_key eql_v2.ore_block_u64_8_256;
    mid integer;
    i integer;
    j integer;
    left_hi integer;
    right_lo integer;
    tmp_id bigint;
    tmp_val eql_v2_encrypted;
    tmp_ore_key eql_v2.ore_block_u64_8_256;
BEGIN
    WHILE lo < hi LOOP
        IF hi - lo <= insertion_threshold THEN
            SELECT q.ids, q.vals, q.ore_keys
                INTO ids, vals, ore_keys
                FROM eql_v2._insertion_sort(ids, vals, ore_keys, lo, hi, strategy) q;
            RETURN;
        END IF;

        -- Median-of-three pivot selection: sort lo, mid, hi then use mid as pivot
        mid := lo + (hi - lo) / 2;

        IF eql_v2._compare_sort_elements(vals, ore_keys, lo, mid, strategy) > 0 THEN
            tmp_id := ids[lo]; ids[lo] := ids[mid]; ids[mid] := tmp_id;
            tmp_val := vals[lo]; vals[lo] := vals[mid]; vals[mid] := tmp_val;
            tmp_ore_key := ore_keys[lo]; ore_keys[lo] := ore_keys[mid]; ore_keys[mid] := tmp_ore_key;
        END IF;
        IF eql_v2._compare_sort_elements(vals, ore_keys, lo, hi, strategy) > 0 THEN
            tmp_id := ids[lo]; ids[lo] := ids[hi]; ids[hi] := tmp_id;
            tmp_val := vals[lo]; vals[lo] := vals[hi]; vals[hi] := tmp_val;
            tmp_ore_key := ore_keys[lo]; ore_keys[lo] := ore_keys[hi]; ore_keys[hi] := tmp_ore_key;
        END IF;
        IF eql_v2._compare_sort_elements(vals, ore_keys, mid, hi, strategy) > 0 THEN
            tmp_id := ids[mid]; ids[mid] := ids[hi]; ids[hi] := tmp_id;
            tmp_val := vals[mid]; vals[mid] := vals[hi]; vals[hi] := tmp_val;
            tmp_ore_key := ore_keys[mid]; ore_keys[mid] := ore_keys[hi]; ore_keys[hi] := tmp_ore_key;
        END IF;

        pivot_val := vals[mid];
        pivot_ore_key := ore_keys[mid];
        i := lo;
        j := hi;

        LOOP
            WHILE eql_v2._compare_sort_pivot(
                vals, ore_keys, i,
                pivot_val, pivot_ore_key, strategy
            ) < 0 LOOP
                i := i + 1;
            END LOOP;
            WHILE eql_v2._compare_sort_pivot(
                vals, ore_keys, j,
                pivot_val, pivot_ore_key, strategy
            ) > 0 LOOP
                j := j - 1;
            END LOOP;

            EXIT WHEN i >= j;

            tmp_id := ids[i]; ids[i] := ids[j]; ids[j] := tmp_id;
            tmp_val := vals[i]; vals[i] := vals[j]; vals[j] := tmp_val;
            tmp_ore_key := ore_keys[i]; ore_keys[i] := ore_keys[j]; ore_keys[j] := tmp_ore_key;

            i := i + 1;
            j := j - 1;
        END LOOP;

        left_hi := j;
        right_lo := j + 1;

        IF left_hi - lo < hi - right_lo THEN
            IF lo < left_hi THEN
                SELECT q.ids, q.vals, q.ore_keys
                    INTO ids, vals, ore_keys
                    FROM eql_v2._quicksort_sorter(ids, vals, ore_keys, lo, left_hi, strategy) q;
            END IF;
            lo := right_lo;
        ELSE
            IF right_lo < hi THEN
                SELECT q.ids, q.vals, q.ore_keys
                    INTO ids, vals, ore_keys
                    FROM eql_v2._quicksort_sorter(ids, vals, ore_keys, right_lo, hi, strategy) q;
            END IF;
            hi := left_hi;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;


--! @internal
--! @brief Emit aligned arrays as rows in ASC or DESC order
--!
--! @param ids bigint[] Array of sorted row identifiers
--! @param vals eql_v2_encrypted[] Array of sorted encrypted values
--! @param direction text Sort direction: 'ASC' (default) or 'DESC'
--! @return TABLE(id bigint, val eql_v2_encrypted) Rows emitted in the requested order
CREATE FUNCTION eql_v2._emit_sorted_rows(
    ids bigint[],
    vals eql_v2_encrypted[],
    direction text DEFAULT 'ASC'
)
RETURNS TABLE(id bigint, val eql_v2_encrypted)
IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    n integer;
    i integer;
BEGIN
    n := coalesce(array_length(ids, 1), 0);

    IF upper(direction) = 'DESC' THEN
        FOR i IN REVERSE n..1 LOOP
            id := ids[i];
            val := vals[i];
            RETURN NEXT;
        END LOOP;
    ELSE
        FOR i IN 1..n LOOP
            id := ids[i];
            val := vals[i];
            RETURN NEXT;
        END LOOP;
    END IF;
END;
$$ LANGUAGE plpgsql;


--! @internal
--! @brief Sort encrypted values using precomputed ORE keys when available
--!
--! Shared implementation for public sorting entrypoints. The \`strategy\`
--! parameter selects the comparison path: \`'ore'\` uses the aligned \`ore_keys\`
--! array; \`'compare'\` falls back to \`eql_v2.compare()\` on the encrypted values
--! directly.
--!
--! @param ids bigint[] Row identifiers aligned with \`vals\`
--! @param vals eql_v2_encrypted[] Encrypted values to sort
--! @param ore_keys eql_v2.ore_block_u64_8_256[] Pre-extracted ORE keys (used when strategy = 'ore')
--! @param direction text Sort direction: 'ASC' (default) or 'DESC'
--! @param strategy text One of 'ore' or 'compare'
--! @return TABLE(id bigint, val eql_v2_encrypted) Sorted rows
CREATE FUNCTION eql_v2._sort_compare_precomputed(
    ids bigint[],
    vals eql_v2_encrypted[],
    ore_keys eql_v2.ore_block_u64_8_256[],
    direction text DEFAULT 'ASC',
    strategy text DEFAULT 'ore'
)
RETURNS TABLE(id bigint, val eql_v2_encrypted)
IMMUTABLE PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    n integer;
    m integer;
    k integer;
    sorted_ids bigint[];
    sorted_vals eql_v2_encrypted[];
    sorted_ore_keys eql_v2.ore_block_u64_8_256[];
BEGIN
    n := coalesce(array_length(ids, 1), 0);
    m := coalesce(array_length(vals, 1), 0);

    IF n <> m THEN
        RAISE EXCEPTION 'ids and vals must have the same length';
    END IF;

    IF strategy = 'ore' THEN
        k := coalesce(array_length(ore_keys, 1), 0);
        IF n <> k THEN
            RAISE EXCEPTION 'ids and ore_keys must have the same length when strategy = ''ore''';
        END IF;
    END IF;

    IF n = 0 THEN
        RETURN;
    END IF;

    IF n = 1 THEN
        id := ids[1];
        val := vals[1];
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT q.ids, q.vals, q.ore_keys
        INTO sorted_ids, sorted_vals, sorted_ore_keys
        FROM eql_v2._quicksort_sorter(ids, vals, ore_keys, 1, n, strategy) q;

    RETURN QUERY
        SELECT emitted.id, emitted.val
        FROM eql_v2._emit_sorted_rows(sorted_ids, sorted_vals, direction) emitted;
END;
$$ LANGUAGE plpgsql;


--! @brief Sort encrypted values using comparison-based quicksort
--!
--! Sorts parallel arrays of identifiers and encrypted values using O(n log n)
--! quicksort with eql_v2.compare(). Returns sorted rows as a table, avoiding
--! the need for unnest() or other array manipulation by callers.
--!
--! When all input rows share an \`ore\` term the sort uses pre-extracted ORE
--! keys; otherwise it falls back to \`eql_v2.compare()\` per pair.
--!
--! This function is designed for environments without operator classes (e.g., Supabase)
--! where direct ORDER BY on encrypted columns is not available.
--!
--! @param ids bigint[] Array of row identifiers
--! @param vals eql_v2_encrypted[] Array of encrypted values (must be same length as ids)
--! @param direction text Sort direction: 'ASC' (default) or 'DESC'
--! @return TABLE(id bigint, val eql_v2_encrypted) Sorted rows
--!
--! @example
--! -- Sort all rows from an encrypted table
--! SELECT * FROM eql_v2.sort_compare(
--!   (SELECT array_agg(id ORDER BY id) FROM ore),
--!   (SELECT array_agg(e ORDER BY id) FROM ore),
--!   'ASC'
--! );
--!
--! -- Sort with a filter
--! SELECT * FROM eql_v2.sort_compare(
--!   (SELECT array_agg(id ORDER BY id) FROM ore WHERE id > 42),
--!   (SELECT array_agg(e ORDER BY id) FROM ore WHERE id > 42),
--!   'DESC'
--! );
--!
--! -- Compose with LIMIT
--! SELECT * FROM eql_v2.sort_compare(
--!   (SELECT array_agg(id ORDER BY id) FROM ore),
--!   (SELECT array_agg(e ORDER BY id) FROM ore)
--! ) LIMIT 5;
--!
--! @see eql_v2.compare
--! @see eql_v2.order_by_compare
CREATE FUNCTION eql_v2.sort_compare(
    ids bigint[],
    vals eql_v2_encrypted[],
    direction text DEFAULT 'ASC'
)
RETURNS TABLE(id bigint, val eql_v2_encrypted)
IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    n integer;
    sorted_ore_keys eql_v2.ore_block_u64_8_256[];
    i integer;
    use_ore boolean := true;
    strategy text;
BEGIN
    n := coalesce(array_length(ids, 1), 0);

    -- Pre-extract sort keys. ORE wins if every non-NULL row carries \`ob\`,
    -- otherwise fall back to eql_v2.compare() per pair.
    FOR i IN 1..n LOOP
        IF vals[i] IS NULL THEN
            sorted_ore_keys[i] := NULL;
        ELSE
            IF use_ore THEN
                IF eql_v2.has_ore_block_u64_8_256(vals[i]) THEN
                    sorted_ore_keys[i] := eql_v2.order_by(vals[i]);
                ELSE
                    use_ore := false;
                END IF;
            END IF;

            EXIT WHEN NOT use_ore;
        END IF;
    END LOOP;

    IF use_ore THEN
        strategy := 'ore';
    ELSE
        strategy := 'compare';
    END IF;

    RETURN QUERY
        SELECT sc.id, sc.val
        FROM eql_v2._sort_compare_precomputed(
            ids, vals, sorted_ore_keys, direction, strategy
        ) sc;
END;
$$ LANGUAGE plpgsql;


--! @brief Sort encrypted values from a table using column and table references
--!
--! Convenience overload that accepts column names, a table name, and an optional
--! filter clause instead of pre-aggregated arrays. Internally constructs the
--! query and delegates to eql_v2.order_by_compare().
--!
--! @param id_column text Name of the bigint identifier column
--! @param val_column text Name of the eql_v2_encrypted value column
--! @param tbl text Table name (may be schema-qualified)
--! @param direction text Sort direction: 'ASC' (default) or 'DESC'
--! @param filter text Optional WHERE clause (without the WHERE keyword)
--! @return TABLE(id bigint, val eql_v2_encrypted) Sorted rows
--!
--! @note The id column must be castable to bigint. Uses dynamic SQL internally.
--! @warning The filter parameter is executed as dynamic SQL. Use only with trusted input.
--!
--! @example
--! -- Sort all rows ascending (default)
--! SELECT * FROM eql_v2.sort_compare('id', 'e', 'ore');
--!
--! -- Sort descending
--! SELECT * FROM eql_v2.sort_compare('id', 'e', 'ore', 'DESC');
--!
--! -- Sort with a filter
--! SELECT * FROM eql_v2.sort_compare('id', 'e', 'ore', 'ASC', 'id > 42');
--!
--! -- Compose with LIMIT
--! SELECT * FROM eql_v2.sort_compare('id', 'e', 'ore') LIMIT 10;
--!
--! @see eql_v2.sort_compare(bigint[], eql_v2_encrypted[], text)
--! @see eql_v2.order_by_compare
CREATE FUNCTION eql_v2.sort_compare(
    id_column text,
    val_column text,
    tbl text,
    direction text DEFAULT 'ASC',
    filter text DEFAULT NULL
)
RETURNS TABLE(id bigint, val eql_v2_encrypted)
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    query text;
    resolved_tbl regclass;
BEGIN
    resolved_tbl := to_regclass(tbl);

    IF resolved_tbl IS NULL THEN
        RAISE EXCEPTION 'table "%" does not exist', tbl;
    END IF;

    query := format('SELECT %I, %I FROM %s', id_column, val_column, resolved_tbl);

    IF filter IS NOT NULL THEN
        query := query || ' WHERE ' || filter;
    END IF;

    RETURN QUERY
        SELECT sc.id, sc.val
        FROM eql_v2.order_by_compare(query, direction) sc;
END;
$$ LANGUAGE plpgsql;


--! @brief Sort encrypted values from a query using comparison-based quicksort
--!
--! Convenience wrapper that accepts a SQL query string, executes it, collects the
--! results, and returns them sorted. For ORE-backed values this pre-extracts the
--! order key once per row and sorts on that key; other inputs fall back to
--! eql_v2.compare(). The query must return exactly two columns: a bigint
--! identifier and an eql_v2_encrypted value.
--!
--! @param query text SQL query returning (bigint, eql_v2_encrypted) columns
--! @param direction text Sort direction: 'ASC' (default) or 'DESC'
--! @return TABLE(id bigint, val eql_v2_encrypted) Sorted rows
--!
--! @note Uses dynamic SQL (EXECUTE) so cannot be IMMUTABLE or PARALLEL SAFE
--! @warning The query parameter is executed as dynamic SQL. Use only with trusted input.
--!
--! @example
--! -- Sort all rows
--! SELECT * FROM eql_v2.order_by_compare('SELECT id, e FROM ore');
--!
--! -- Sort with WHERE clause
--! SELECT * FROM eql_v2.order_by_compare(
--!   'SELECT id, e FROM ore WHERE id > 42',
--!   'DESC'
--! );
--!
--! @see eql_v2.sort_compare
--! @see eql_v2.compare
CREATE FUNCTION eql_v2.order_by_compare(
    query text,
    direction text DEFAULT 'ASC'
)
RETURNS TABLE(id bigint, val eql_v2_encrypted)
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
    all_ids bigint[];
    all_vals eql_v2_encrypted[];
    all_ore_keys eql_v2.ore_block_u64_8_256[];
    all_have_ore_keys boolean;
    strategy text;
BEGIN
    -- Pre-extract sort keys. ORE wins if every non-NULL row carries \`ob\`,
    -- otherwise fall back to eql_v2.compare() per pair.
    EXECUTE format(
        'WITH input_rows AS (
            SELECT row_number() OVER () AS ord,
                   sub.id,
                   sub.val,
                   CASE
                       WHEN sub.val IS NULL THEN NULL
                       WHEN eql_v2.has_ore_block_u64_8_256(sub.val) THEN eql_v2.order_by(sub.val)
                       ELSE NULL
                   END AS ore_key,
                   CASE
                       WHEN sub.val IS NULL THEN TRUE
                       ELSE eql_v2.has_ore_block_u64_8_256(sub.val)
                   END AS has_ore_key
            FROM (%s) sub(id, val)
         )
         SELECT array_agg(id ORDER BY ord),
                array_agg(val ORDER BY ord),
                array_agg(ore_key ORDER BY ord),
                coalesce(bool_and(has_ore_key), TRUE)
         FROM input_rows',
        query
    ) INTO all_ids, all_vals, all_ore_keys, all_have_ore_keys;

    IF all_ids IS NULL THEN
        RETURN;
    END IF;

    IF all_have_ore_keys THEN
        strategy := 'ore';
    ELSE
        strategy := 'compare';
    END IF;

    RETURN QUERY
        SELECT sc.id, sc.val
        FROM eql_v2._sort_compare_precomputed(
            all_ids,
            all_vals,
            all_ore_keys,
            direction,
            strategy
        ) sc;
END;
$$ LANGUAGE plpgsql;

--! @file src/operators/operator_class.sql
--! @brief Btree operator class for the \`eql_v2_encrypted\` composite type
--!
--! \`eql_v2_encrypted\` is a composite type. PostgreSQL gives every composite
--! type an implicit row-wise btree comparison (\`record_ops\`) — but that
--! compares the raw ciphertext byte-for-byte, so two encryptions of the same
--! plaintext (same \`hm\`, different \`c\`) would sort and group as *distinct*.
--! \`eql_v2.encrypted_operator_class\` is registered \`DEFAULT ... USING btree\`
--! specifically to override \`record_ops\` with a comparison that is correct
--! for encrypted data: \`GROUP BY\`, \`DISTINCT\`, \`ORDER BY\`, sort-merge joins
--! and \`ANALYZE\` on a bare \`eql_v2_encrypted\` column all route through
--! FUNCTION 1 below.
--!
--! @note FUNCTION 1 is \`eql_v2.encrypted_btree_compare\`, NOT the strict
--!       \`eql_v2.compare\`. A btree support function must be total and must
--!       never raise — \`ANALYZE\` calls it to build column statistics on
--!       every encrypted column. \`eql_v2.compare\` is deliberately strict
--!       (it raises without a Block-ORE \`ob\` term — see U-005); it backs
--!       the \`<\` / \`>\` range operators, not this opclass.
--!
--! @note Functional indexes are the canonical recipe for *building* indexes
--!       on encrypted columns (see U-001 and docs/reference/database-indexes.md).
--!       This opclass exists to keep the composite type's built-in
--!       comparison correct — not as an index-building recommendation.
--!
--! @see eql_v2.encrypted_hash_operator_class (hash — GROUP BY / hash joins)
--! @see eql_v2.compare

--------------------

--! @brief Total, non-raising btree comparator for \`eql_v2_encrypted\`
--!
--! Three-way comparison (\`-1\` / \`0\` / \`1\`) used as FUNCTION 1 of
--! \`eql_v2.encrypted_operator_class\`. Unlike \`eql_v2.compare\`, it never
--! raises: a btree support function is invoked by \`ANALYZE\`, sort, and
--! \`GROUP BY\` on every value, so raising is not an option.
--!
--! Comparison priority:
--!   1. Both operands carry \`ob\` (Block ORE) — order-preserving comparison
--!      via \`eql_v2.compare_ore_block_u64_8_256\`.
--!   2. Both operands carry \`hm\` (HMAC-256) — a total order on the hmac
--!      bytes. Not order-preserving on plaintext (hmac is not), but
--!      deterministic, total, and \`= 0\` exactly when the hmac terms match
--!      — consistent with the \`=\` operator, so \`GROUP BY\` / \`DISTINCT\`
--!      deduplicate correctly.
--!   3. Otherwise — a deterministic order on the raw payload. Reached only
--!      for term-less / mixed payloads; present so the function stays total.
--!
--! @param a eql_v2_encrypted First value
--! @param b eql_v2_encrypted Second value
--! @return integer -1, 0, or 1
--!
--! @internal
--! @see eql_v2.encrypted_operator_class
--! @see eql_v2.compare
CREATE FUNCTION eql_v2.encrypted_btree_compare(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    hm_a text;
    hm_b text;
  BEGIN
    -- Block ORE on both sides: order-preserving comparison.
    IF eql_v2.has_ore_block_u64_8_256(a) AND eql_v2.has_ore_block_u64_8_256(b) THEN
      RETURN eql_v2.compare_ore_block_u64_8_256(a, b);
    END IF;

    -- HMAC on both sides: total order on the hmac bytes. \`= 0\` iff the hmac
    -- terms match, consistent with the \`=\` operator and the hash opclass.
    hm_a := eql_v2.hmac_256(a)::text;
    hm_b := eql_v2.hmac_256(b)::text;
    IF hm_a IS NOT NULL AND hm_b IS NOT NULL THEN
      RETURN CASE
        WHEN hm_a < hm_b THEN -1
        WHEN hm_a > hm_b THEN 1
        ELSE 0
      END;
    END IF;

    -- Fallback for term-less / mixed payloads: a deterministic, non-raising
    -- total order on the raw payload. Not a normal column shape — this
    -- branch only keeps the btree FUNCTION 1 contract (total, never raises).
    RETURN CASE
      WHEN (a).data::text < (b).data::text THEN -1
      WHEN (a).data::text > (b).data::text THEN 1
      ELSE 0
    END;
  END;
$$ LANGUAGE plpgsql;

--------------------

CREATE OPERATOR FAMILY eql_v2.encrypted_operator_family USING btree;

CREATE OPERATOR CLASS eql_v2.encrypted_operator_class DEFAULT FOR TYPE eql_v2_encrypted USING btree FAMILY eql_v2.encrypted_operator_family AS
  OPERATOR 1 <,
  OPERATOR 2 <=,
  OPERATOR 3 =,
  OPERATOR 4 >=,
  OPERATOR 5 >,
  FUNCTION 1 eql_v2.encrypted_btree_compare(a eql_v2_encrypted, b eql_v2_encrypted);

--! @brief PostgreSQL hash operator class for encrypted value hashing
--!
--! Defines the hash operator family and operator class required for hash-based
--! operations on encrypted values. This enables PostgreSQL to use hash strategies for:
--! - Hash joins (cross-row equality via hash)
--! - GROUP BY (hash aggregation)
--! - DISTINCT (hash-based deduplication)
--! - UNION (hash-based set operations)
--!
--! Only the same-type equality operator (eql_v2_encrypted = eql_v2_encrypted) is
--! registered. Cross-type operators (encrypted/jsonb) are excluded because hash
--! joins require independent hashing of each side before comparison.
--!
--! @note Requires hmac_256 index terms for correct hashing
--! @see eql_v2.hash_encrypted
--! @see eql_v2.encrypted_operator_class (btree)

CREATE OPERATOR FAMILY eql_v2.encrypted_hash_operator_family USING hash;

CREATE OPERATOR CLASS eql_v2.encrypted_hash_operator_class
  DEFAULT FOR TYPE eql_v2_encrypted USING hash
  FAMILY eql_v2.encrypted_hash_operator_family AS
    OPERATOR 1 = (eql_v2_encrypted, eql_v2_encrypted),
    FUNCTION 1 eql_v2.hash_encrypted(eql_v2_encrypted);

--! @brief Contained-by operator for encrypted values (<@)
--!
--! Implements the <@ (contained-by) operator for testing if left encrypted value
--! is contained by the right encrypted value. Uses ste_vec (secure tree encoding vector)
--! index terms for containment testing without decryption. Reverse of @> operator.
--!
--! Primarily used for encrypted array or set containment queries.
--!
--! @param a eql_v2_encrypted Left operand (contained value)
--! @param b eql_v2_encrypted Right operand (container)
--! @return Boolean True if a is contained by b
--!
--! @example
--! -- Check if value is contained in encrypted array
--! SELECT * FROM documents
--! WHERE '["security"]'::jsonb::eql_v2_encrypted <@ encrypted_tags;
--!
--! @note Requires ste_vec index configuration
--! @see eql_v2.ste_vec_contains
--! @see eql_v2.\\"@>\\"
--! @see eql_v2.add_search_config

-- Marked IMMUTABLE STRICT PARALLEL SAFE — see operators/@>.sql for rationale.
CREATE FUNCTION eql_v2."<@"(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  -- Contains with reversed arguments
  SELECT eql_v2.ste_vec_contains(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v2."<@",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted
);


--! @brief Contained-by operator (<@) with an \`eql_v2.stevec_query\` LHS
--!
--! Reverse of \`@>(eql_v2_encrypted, eql_v2.stevec_query)\`. Mirrors the
--! typed needle convention: "is this query payload contained in that
--! encrypted document?".
--!
--! @param a eql_v2.stevec_query Left operand (query payload)
--! @param b eql_v2_encrypted Right operand (container)
--! @return Boolean True if \`b\` contains \`a\`
--! @see eql_v2."@>"(eql_v2_encrypted, eql_v2.stevec_query)
CREATE FUNCTION eql_v2."<@"(a eql_v2.stevec_query, b eql_v2_encrypted)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2."@>"(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v2."<@",
  LEFTARG=eql_v2.stevec_query,
  RIGHTARG=eql_v2_encrypted
);


--! @brief Contained-by operator (<@) with an \`eql_v2.ste_vec_entry\` LHS
--!
--! Reverse of \`@>(eql_v2_encrypted, eql_v2.ste_vec_entry)\`. Convenience
--! shape for "is this entry contained in that encrypted document?".
--!
--! @param a eql_v2.ste_vec_entry Left operand (single entry)
--! @param b eql_v2_encrypted Right operand (container)
--! @return Boolean True if \`b\` contains \`a\`
--! @see eql_v2."@>"(eql_v2_encrypted, eql_v2.ste_vec_entry)
CREATE FUNCTION eql_v2."<@"(a eql_v2.ste_vec_entry, b eql_v2_encrypted)
RETURNS boolean
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2."@>"(b, a)
$$;

CREATE OPERATOR <@(
  FUNCTION=eql_v2."<@",
  LEFTARG=eql_v2.ste_vec_entry,
  RIGHTARG=eql_v2_encrypted
);

--! @brief Inequality helper for encrypted values
--! @internal
--!
--! Inlinable SQL helper mirroring the \`<>\` operator's body: reduces to
--! \`hmac_256(a) <> hmac_256(b)\`. Kept for callers that invoked the
--! pre-#193 form (\`eql_v2.neq\`); equivalent to using the \`<>\` operator
--! directly.
--!
--! Inequality on \`eql_v2_encrypted\` is strictly hmac-based (see U-002).
--! Returns NULL when either side lacks an \`hm\` term — matching the
--! \`<>\` operator's behaviour.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return Boolean True if hmac terms differ
--!
--! @see eql_v2."<>"
--! @see eql_v2.hmac_256
CREATE FUNCTION eql_v2.neq(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a) <> eql_v2.hmac_256(b)
$$;

--! @brief Not-equal operator for encrypted values
--!
--! Implements the <> (not equal) operator for comparing encrypted values using their
--! encrypted index terms. Enables WHERE clause inequality comparisons without decryption.
--!
--! @param a eql_v2_encrypted Left operand
--! @param b eql_v2_encrypted Right operand
--! @return Boolean True if encrypted values are not equal
--!
--! @example
--! -- Find records with non-matching values
--! SELECT * FROM users
--! WHERE encrypted_email <> 'admin@example.com'::text::eql_v2_encrypted;
--!
--! @see eql_v2.compare
--! @see eql_v2."="
-- Inlinable; mirrors \`=\` (see operators/=.sql for rationale).
-- Returns NULL on ORE-only encrypted columns (no \`hm\` field) instead
-- of falling back to a slower comparison path; surface the config
-- error rather than hide it.
CREATE FUNCTION eql_v2."<>"(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a) <> eql_v2.hmac_256(b)
$$;


CREATE OPERATOR <> (
  FUNCTION=eql_v2."<>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted,
  NEGATOR = =,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

--! @brief <> operator for encrypted value and JSONB
--! @see eql_v2."<>"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."<>"(a eql_v2_encrypted, b jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a) <> eql_v2.hmac_256(b::eql_v2_encrypted)
$$;

CREATE OPERATOR <> (
  FUNCTION=eql_v2."<>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=jsonb,
  NEGATOR = =,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);

--! @brief <> operator for JSONB and encrypted value
--!
--! @param jsonb Plain JSONB value
--! @param eql_v2_encrypted Encrypted value
--! @return boolean True if values are not equal
--!
--! @see eql_v2."<>"(eql_v2_encrypted, eql_v2_encrypted)
CREATE FUNCTION eql_v2."<>"(a jsonb, b eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.hmac_256(a::eql_v2_encrypted) <> eql_v2.hmac_256(b)
$$;

CREATE OPERATOR <> (
  FUNCTION=eql_v2."<>",
  LEFTARG=jsonb,
  RIGHTARG=eql_v2_encrypted,
  NEGATOR = =,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  MERGES
);





--! @brief JSONB field accessor operator alias (->>)
--!
--! Implements the ->> operator as an alias of -> for encrypted JSONB data. This mirrors
--! PostgreSQL semantics where ->> returns text via implicit casts. The underlying
--! implementation delegates to eql_v2."->" and allows PostgreSQL to coerce the result.
--!
--! Provides two overloads:
--! - (eql_v2_encrypted, text) - Field name selector
--! - (eql_v2_encrypted, eql_v2_encrypted) - Encrypted selector
--!
--! @see eql_v2."->"
--! @see eql_v2.selector

--! @brief ->> operator with text selector
--! @param eql_v2_encrypted Encrypted JSONB data
--! @param text Field name to extract
--! @return text Encrypted value at selector, implicitly cast from eql_v2_encrypted
--! @example
--! SELECT encrypted_json ->> 'field_name' FROM table;
CREATE FUNCTION eql_v2."->>"(e eql_v2_encrypted, selector text)
  RETURNS text
IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    found eql_v2_encrypted;
	BEGIN
    -- found = eql_v2."->"(e, selector);
    -- RETURN eql_v2.ciphertext(found);
    RETURN eql_v2."->"(e, selector);
  END;
$$ LANGUAGE plpgsql;


CREATE OPERATOR ->> (
  FUNCTION=eql_v2."->>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=text
);



---------------------------------------------------

--! @brief ->> operator with encrypted selector
--! @param e eql_v2_encrypted Encrypted JSONB data
--! @param selector eql_v2_encrypted Encrypted field selector
--! @return text Encrypted value at selector, implicitly cast from eql_v2_encrypted
--! @see eql_v2."->>"(eql_v2_encrypted, text)
CREATE FUNCTION eql_v2."->>"(e eql_v2_encrypted, selector eql_v2_encrypted)
  RETURNS text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    RETURN eql_v2."->>"(e, eql_v2._selector(selector));
  END;
$$ LANGUAGE plpgsql;


CREATE OPERATOR ->> (
  FUNCTION=eql_v2."->>",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted
);

--! @brief JSONB field accessor operator for encrypted values (->)
--!
--! Implements the -> operator to access fields/elements from encrypted JSONB data.
--! Returns the matching sv entry as \`eql_v2.ste_vec_entry\` (or NULL on miss).
--!
--! Encrypted JSON is represented as an array of sv elements in the
--! StEVec format. Each element has a selector, ciphertext, and index
--! terms: \`{"sv": [{"c": "...", "s": "...", "hm": "..."}, ...]}\`.
--!
--! Provides three overloads:
--! - (eql_v2_encrypted, text) - Field name selector
--! - (eql_v2_encrypted, eql_v2_encrypted) - Encrypted selector
--! - (eql_v2_encrypted, integer) - Array index selector (0-based)
--!
--! All three return \`eql_v2.ste_vec_entry\` and preserve the source
--! payload's root \`i\` / \`v\` envelope metadata in the returned entry
--! (the DOMAIN CHECK on \`ste_vec_entry\` doesn't forbid extra fields).
--!
--! @note Operator resolution: Assignment casts are considered (PostgreSQL standard behavior).
--! To use text selector, parameter may need explicit cast to text.
--!
--! @see eql_v2.ste_vec_entry
--! @see eql_v2.selector
--! @see eql_v2."->>"

--! @brief -> operator with text selector
--!
--! Returns the sv entry whose \`s\` selector equals @p selector, with
--! the source payload's \`i\` / \`v\` metadata merged in. Selectors are
--! deterministic per (path, key) within a document, so at most one
--! entry matches; \`jsonb_path_query_first\` returns the first match
--! and stops scanning.
--!
--! Inlinable single-statement SQL: the planner folds this body into
--! the calling query, so \`WHERE col -> 'sel' = $1\` reduces structurally
--! to \`eql_v2.eq_term(col -> 'sel') = eql_v2.eq_term($1)\` and matches
--! a functional index built on \`eql_v2.eq_term(col -> 'sel')\`.
--!
--! @param e eql_v2_encrypted Encrypted JSONB payload (root)
--! @param selector text Selector hash (the \`s\` field value)
--! @return eql_v2.ste_vec_entry Matching entry merged with root meta,
--!         NULL if no element matches.
--!
--! @note The returned entry carries \`i\` / \`v\` from the root in addition
--!       to the sv-element fields. This is intentional: per-entry
--!       extractors (\`eql_v2.eq_term\`, \`eql_v2.ore_cllw\`, ...) read
--!       only their own fields and ignore \`i\` / \`v\`; callers that need
--!       the root envelope (e.g. for decryption) still see it.
--!
--! @example
--! SELECT encrypted_json -> 'field_name' FROM table;
CREATE FUNCTION eql_v2."->"(e eql_v2_encrypted, selector text)
  RETURNS eql_v2.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (
    eql_v2.meta_data(e) ||
    jsonb_path_query_first(
      (e).data,
      '$.sv[*] ? (@.s == $sel)'::jsonpath,
      jsonb_build_object('sel', selector)
    )
  )::eql_v2.ste_vec_entry
$$;


CREATE OPERATOR ->(
  FUNCTION=eql_v2."->",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=text
);

---------------------------------------------------

--! @brief -> operator with encrypted selector
--!
--! Convenience overload: extracts the selector text from an encrypted
--! selector payload and delegates to the (text) form. Inlinable.
--!
--! @param e eql_v2_encrypted Encrypted JSONB data
--! @param selector eql_v2_encrypted Encrypted selector payload
--! @return eql_v2.ste_vec_entry Matching entry, NULL on miss
--! @see eql_v2."->"(eql_v2_encrypted, text)
CREATE FUNCTION eql_v2."->"(e eql_v2_encrypted, selector eql_v2_encrypted)
  RETURNS eql_v2.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2."->"(e, eql_v2._selector(selector))
$$;



CREATE OPERATOR ->(
  FUNCTION=eql_v2."->",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=eql_v2_encrypted
);


---------------------------------------------------

--! @brief -> operator with integer array index
--!
--! Returns the sv entry at the given (0-based, JSONB-style) array
--! index, merged with the root payload's \`i\` / \`v\` metadata. Returns
--! NULL when the underlying value isn't an sv-array payload or when
--! the index is out of bounds.
--!
--! @param e eql_v2_encrypted Encrypted sv-array payload
--! @param selector integer Array index (0-based, JSONB convention)
--! @return eql_v2.ste_vec_entry Matching entry, NULL on miss
--! @note Array index is 0-based (JSONB standard) despite PostgreSQL arrays being 1-based
--! @example
--! SELECT encrypted_array -> 0 FROM table;
--! @see eql_v2.is_ste_vec_array
CREATE FUNCTION eql_v2."->"(e eql_v2_encrypted, selector integer)
  RETURNS eql_v2.ste_vec_entry
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN eql_v2.is_ste_vec_array(e) THEN
      (eql_v2.meta_data(e) || ((e).data -> 'sv' -> selector))::eql_v2.ste_vec_entry
    ELSE NULL
  END
$$;





CREATE OPERATOR ->(
  FUNCTION=eql_v2."->",
  LEFTARG=eql_v2_encrypted,
  RIGHTARG=integer
);


--! @brief EQL lint: detect non-inlinable operator implementation functions
--!
--! Returns one row per violation found in the installed EQL surface. The
--! Postgres planner can only inline a function during index matching when:
--!
--!   * \`LANGUAGE sql\` (plpgsql / C / etc. cannot be inlined)
--!   * \`IMMUTABLE\` or \`STABLE\` volatility (VOLATILE cannot be inlined into
--!     index expressions)
--!   * No \`SET\` clauses (e.g. \`SET search_path = ...\`)
--!   * Not \`SECURITY DEFINER\`
--!   * Single-statement SELECT body
--!
--! @note The single-statement SELECT body condition is **not yet checked** by
--! this lint. A \`LANGUAGE sql\` function with a multi-statement body, a CTE,
--! or any pre-SELECT statement will pass all four implemented checks while
--! remaining non-inlinable. Implementing the check requires walking \`prosrc\`
--! (or \`pg_get_functiondef\`); tracked as a follow-up to #194.
--!
--! Operators on encrypted types (\`eql_v2_encrypted\`, \`eql_v2.bloom_filter\`,
--! \`eql_v2.ore_*\`, etc.) whose implementation functions fail any of these
--! rules silently fall back to seq scan when the documented functional
--! indexes (\`eql_v2.hmac_256(col)\`, \`eql_v2.bloom_filter(col)\`,
--! \`eql_v2.ste_vec(col)\`) are in place. This lint surfaces every such case.
--!
--! Severity:
--!   \`error\`   — fixable, blocks index matching, ship-blocking.
--!   \`warning\` — likely-fixable, may not block matching but signals intent.
--!   \`info\`    — observational; useful for review, not a defect on its own.
--!
--! Categories:
--!   \`inlinability_language\`   — implementation function isn't \`LANGUAGE sql\`.
--!   \`inlinability_volatility\` — implementation function is VOLATILE.
--!   \`inlinability_set_clause\` — implementation function has a \`SET\` clause.
--!   \`inlinability_secdef\`     — implementation function is \`SECURITY DEFINER\`.
--!   \`inlinability_transitive\` — implementation function is itself inlinable
--!                                but its body invokes a non-inlinable function
--!                                (depth 1; the planner can't peek through
--!                                that boundary).
--!
--! @example
--! \`\`\`
--! SELECT severity, category, object_name, message
--!   FROM eql_v2.lints()
--!  WHERE severity = 'error'
--!  ORDER BY category, object_name;
--! \`\`\`
--!
--! @return SETOF record (severity text, category text, object_name text, message text)
CREATE OR REPLACE FUNCTION eql_v2.lints()
RETURNS TABLE (
  severity text,
  category text,
  object_name text,
  message text
)
LANGUAGE sql STABLE
AS $$
  WITH
  -- All operators where at least one operand involves an EQL type. Limits
  -- the scope of the lint to the operator surface customers actually hit
  -- via SQL (\`col = val\`, \`col LIKE '...'\`, \`col @> '...'\` and friends).
  eql_operators AS (
    SELECT
      op.oid              AS oprid,
      op.oprname          AS opname,
      op.oprcode          AS implfunc,
      op.oprleft::regtype AS lhs,
      op.oprright::regtype AS rhs,
      op.oprcode::regprocedure AS impl_signature
    FROM pg_operator op
    WHERE EXISTS (
        SELECT 1 FROM pg_type t
         WHERE t.oid IN (op.oprleft, op.oprright)
           AND (t.typname LIKE 'eql_v2%'
             OR t.typnamespace = 'eql_v2'::regnamespace)
      )
  ),

  -- Cross-join with each operator's implementation function metadata.
  -- One row per operator; columns describe the inlinability of the impl.
  op_impl AS (
    SELECT
      eo.opname,
      eo.lhs,
      eo.rhs,
      eo.impl_signature::text                       AS impl_signature,
      lang_l.lanname                                AS lang,
      p.provolatile                                 AS volatility,
      p.proconfig                                   AS config,
      p.prosecdef                                   AS secdef,
      p.prosrc                                      AS body
    FROM eql_operators eo
    JOIN pg_proc p ON p.oid = eo.implfunc
    JOIN pg_language lang_l ON lang_l.oid = p.prolang
  )

  -- ┌─────────────────────────────────────────────────────────────────┐
  -- │ Direct inlinability checks: each row examines one operator's    │
  -- │ implementation function and emits a violation if any rule is    │
  -- │ broken. Multiple violations on the same function become         │
  -- │ multiple rows (developers see every reason it doesn't inline).  │
  -- └─────────────────────────────────────────────────────────────────┘

  SELECT
    'error'                                                             AS severity,
    'inlinability_language'                                             AS category,
    format('operator %s(%s, %s) -> %s',
           opname, lhs, rhs, impl_signature)                            AS object_name,
    format(
      'Operator implementation function is \`LANGUAGE %s\`; only \`LANGUAGE sql\` functions can be inlined by the planner. Bare \`col %s val\` queries fall back to seq scan even when a matching functional index exists.',
      lang, opname)                                                     AS message
  FROM op_impl
  WHERE lang <> 'sql'

  UNION ALL

  SELECT
    'error',
    'inlinability_volatility',
    format('operator %s(%s, %s) -> %s', opname, lhs, rhs, impl_signature),
    format(
      'Operator implementation function is \`VOLATILE\`. The Postgres planner refuses to inline volatile functions into index expressions, so functional indexes never engage. Mark the function \`IMMUTABLE\` (or \`STABLE\` if it depends on session state).',
      opname)
  FROM op_impl
  WHERE volatility = 'v'

  UNION ALL

  SELECT
    'error',
    'inlinability_set_clause',
    format('operator %s(%s, %s) -> %s', opname, lhs, rhs, impl_signature),
    format(
      'Operator implementation function has a \`SET\` clause (e.g. \`SET search_path = ...\`). Per Postgres function-inlining rules, any \`SET\` clause blocks inlining. Use schema-qualified identifiers in the body and remove the \`SET\` clause to allow the planner to inline.')
  FROM op_impl
  WHERE config IS NOT NULL

  UNION ALL

  SELECT
    'error',
    'inlinability_secdef',
    format('operator %s(%s, %s) -> %s', opname, lhs, rhs, impl_signature),
    'Operator implementation function is \`SECURITY DEFINER\`. Such functions cannot be inlined; remove \`SECURITY DEFINER\` or use a non-inlinable wrapper layer.'
  FROM op_impl
  WHERE secdef

  -- ┌─────────────────────────────────────────────────────────────────┐
  -- │ Transitive inlinability: an operator implementation function    │
  -- │ that's itself inlinable can still fail to inline if its body    │
  -- │ calls a non-inlinable function. Walk one level via pg_depend.   │
  -- │                                                                 │
  -- │ Postgres records function-to-function dependencies in           │
  -- │ pg_depend with deptype 'n' (normal) when one function references│
  -- │ another in its body — but only at CREATE time and only for      │
  -- │ direct calls. This is good enough for v1; deeper transitive     │
  -- │ analysis is a follow-up.                                        │
  -- └─────────────────────────────────────────────────────────────────┘

  UNION ALL

  SELECT
    'error',
    'inlinability_transitive',
    format('operator %s(%s, %s) -> %s', oi.opname, oi.lhs, oi.rhs,
           oi.impl_signature),
    format(
      'Operator implementation function is inlinable but invokes non-inlinable function \`%s\` (lang=%s, volatility=%s%s). The chain blocks at depth 1: the planner inlines the outer call but cannot reduce the inner call into an index expression.',
      called.proname,
      called_lang.lanname,
      CASE called.provolatile
        WHEN 'i' THEN 'IMMUTABLE'
        WHEN 's' THEN 'STABLE'
        WHEN 'v' THEN 'VOLATILE'
      END,
      CASE WHEN called.proconfig IS NOT NULL
           THEN ', has SET clause'
           ELSE '' END)
  FROM op_impl oi
  -- Only worth the transitive check if the outer function is otherwise
  -- inlinable — otherwise the direct lints above already report it.
  JOIN pg_proc outer_p ON outer_p.oid = oi.impl_signature::regprocedure
  JOIN pg_depend d
    ON d.classid = 'pg_proc'::regclass
   AND d.objid = outer_p.oid
   AND d.refclassid = 'pg_proc'::regclass
   AND d.deptype = 'n'
  JOIN pg_proc called ON called.oid = d.refobjid
  JOIN pg_language called_lang ON called_lang.oid = called.prolang
  WHERE oi.lang = 'sql'
    AND oi.volatility IN ('i', 's')
    AND oi.config IS NULL
    AND NOT oi.secdef
    AND called.oid <> outer_p.oid
    AND (
         called_lang.lanname <> 'sql'
      OR called.provolatile = 'v'
      OR called.proconfig IS NOT NULL
      OR called.prosecdef
    )

  ORDER BY 1, 2, 3;
$$;

COMMENT ON FUNCTION eql_v2.lints() IS
  'EQL lint: returns one row per non-inlinable operator implementation. '
  'Run \`SELECT * FROM eql_v2.lints() WHERE severity = ''error''\` for a '
  'CI-gateable check that all operator implementations on EQL types are '
  'eligible for planner inlining.';

--! @file jsonb/functions.sql
--! @brief JSONB path query and array manipulation functions for encrypted data
--!
--! These functions provide PostgreSQL-compatible operations on encrypted JSONB values
--! using Structured Transparent Encryption (STE). They support:
--! - Path-based queries to extract nested encrypted values
--! - Existence checks for encrypted fields
--! - Array operations (length, elements extraction)
--! - Field-level HMAC term extraction for equality / GROUP BY / DISTINCT
--!
--! @note STE stores encrypted JSONB as a vector of encrypted elements ('sv') with selectors
--! @note Functions suppress errors for missing fields, type mismatches (similar to PostgreSQL jsonpath)
--! @note \`selector\` parameters in this module are *encrypted-side* selector
--!       hashes — the deterministic hash that the crypto layer (e.g.
--!       \`@cipherstash/protect\`) emits in the \`s\` field of each \`sv\` element
--!       (e.g. \`'a7cea93975ed8c01f861ccb6bd082784'\`). Plaintext JSONPaths
--!       like \`'$.address.city'\` are never accepted at runtime; the proxy /
--!       client rewrites them to selector hashes before the query reaches EQL.


--! @brief Query encrypted JSONB for elements matching selector
--!
--! Searches the Structured Transparent Encryption (STE) vector for elements matching
--! the given selector path. Returns all matching encrypted elements. If multiple
--! matches form an array, they are wrapped with array metadata.
--!
--! @param jsonb Encrypted JSONB payload containing STE vector ('sv')
--! @param text Path selector to match against encrypted elements
--! @return SETOF eql_v2_encrypted Matching encrypted elements (may return multiple rows)
--!
--! @note Returns empty set if selector is not found (does not throw exception)
--! @note Array elements use same selector; multiple matches wrapped with 'a' flag
--! @note Returns a set containing NULL if val is NULL; returns empty set if no matches found
--! @see eql_v2.jsonb_path_query_first
--! @see eql_v2.jsonb_path_exists
CREATE FUNCTION eql_v2.jsonb_path_query(val jsonb, selector text)
  RETURNS SETOF eql_v2_encrypted
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT
    CASE
      WHEN bool_or(eql_v2.is_ste_vec_array(elem)) THEN
        (eql_v2.meta_data(val) || jsonb_build_object('sv', jsonb_agg(elem), 'a', 1))::eql_v2_encrypted
      ELSE
        (eql_v2.meta_data(val) || (array_agg(elem))[1])::eql_v2_encrypted
    END
  FROM jsonb_array_elements(val -> 'sv') elem
  WHERE elem ->> 's' = selector
  HAVING count(*) > 0
$$;


--! @brief Query encrypted JSONB with encrypted selector
--!
--! Overload that accepts encrypted selector and extracts its plaintext value
--! before delegating to main jsonb_path_query implementation.
--!
--! @param val eql_v2_encrypted Encrypted JSONB value to query
--! @param selector eql_v2_encrypted Encrypted selector to match against
--! @return SETOF eql_v2_encrypted Matching encrypted elements
--!
--! @see eql_v2.jsonb_path_query(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_query(val eql_v2_encrypted, selector eql_v2_encrypted)
  RETURNS SETOF eql_v2_encrypted
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT * FROM eql_v2.jsonb_path_query((val).data, eql_v2._selector(selector));
$$;


--! @brief Query encrypted JSONB with text selector
--!
--! Overload that accepts encrypted JSONB value and text selector,
--! extracting the JSONB payload before querying.
--!
--! @param eql_v2_encrypted Encrypted JSONB value to query
--! @param text Path selector to match against
--! @return SETOF eql_v2_encrypted Matching encrypted elements
--!
--! @example
--! -- Query encrypted JSONB for the sv element at a given selector hash
--! SELECT * FROM eql_v2.jsonb_path_query(encrypted_document, 'a7cea93975ed8c01f861ccb6bd082784');
--!
--! @see eql_v2.jsonb_path_query(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_query(val eql_v2_encrypted, selector text)
  RETURNS SETOF eql_v2_encrypted
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT * FROM eql_v2.jsonb_path_query((val).data, selector);
$$;


------------------------------------------------------------------------------------


--! @brief Check if selector path exists in encrypted JSONB
--!
--! Tests whether any encrypted elements match the given selector path.
--! More efficient than jsonb_path_query when only existence check is needed.
--!
--! @param jsonb Encrypted JSONB payload to check
--! @param text Path selector to test
--! @return boolean True if matching element exists, false otherwise
--!
--! @see eql_v2.jsonb_path_query(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_exists(val jsonb, selector text)
  RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM jsonb_array_elements(val -> 'sv') elem
    WHERE elem ->> 's' = selector
  );
$$;


--! @brief Check existence with encrypted selector
--!
--! Overload that accepts encrypted selector and extracts its value
--! before checking existence.
--!
--! @param val eql_v2_encrypted Encrypted JSONB value to check
--! @param selector eql_v2_encrypted Encrypted selector to test
--! @return boolean True if path exists
--!
--! @see eql_v2.jsonb_path_exists(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_exists(val eql_v2_encrypted, selector eql_v2_encrypted)
  RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.jsonb_path_exists((val).data, eql_v2._selector(selector));
$$;


--! @brief Check existence with text selector
--!
--! Overload that accepts encrypted JSONB value and text selector.
--!
--! @param eql_v2_encrypted Encrypted JSONB value to check
--! @param text Path selector to test
--! @return boolean True if path exists
--!
--! @example
--! -- Check if the encrypted document has an sv element at a given selector hash
--! SELECT eql_v2.jsonb_path_exists(encrypted_document, 'a7cea93975ed8c01f861ccb6bd082784');
--!
--! @see eql_v2.jsonb_path_exists(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_exists(val eql_v2_encrypted, selector text)
  RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.jsonb_path_exists((val).data, selector);
$$;


------------------------------------------------------------------------------------


--! @brief Get first element matching selector
--!
--! Returns only the first encrypted element matching the selector path,
--! or NULL if no match found. More efficient than jsonb_path_query when
--! only one result is needed.
--!
--! @param jsonb Encrypted JSONB payload to query
--! @param text Path selector to match
--! @return eql_v2_encrypted First matching element or NULL
--!
--! @note Uses LIMIT 1 internally for efficiency
--! @see eql_v2.jsonb_path_query(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_query_first(val jsonb, selector text)
  RETURNS eql_v2_encrypted
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT (eql_v2.meta_data(val) || elem)::eql_v2_encrypted
  FROM jsonb_array_elements(val -> 'sv') elem
  WHERE elem ->> 's' = selector
  LIMIT 1
$$;


--! @brief Get first element with encrypted selector
--!
--! Overload that accepts encrypted selector and extracts its value
--! before querying for first match.
--!
--! @param val eql_v2_encrypted Encrypted JSONB value to query
--! @param selector eql_v2_encrypted Encrypted selector to match
--! @return eql_v2_encrypted First matching element or NULL
--!
--! @see eql_v2.jsonb_path_query_first(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_query_first(val eql_v2_encrypted, selector eql_v2_encrypted)
  RETURNS eql_v2_encrypted
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.jsonb_path_query_first((val).data, eql_v2._selector(selector));
$$;


--! @brief Get first element with text selector
--!
--! Overload that accepts encrypted JSONB value and text selector.
--!
--! @param eql_v2_encrypted Encrypted JSONB value to query
--! @param text Path selector to match
--! @return eql_v2_encrypted First matching element or NULL
--!
--! @example
--! -- Get the first matching sv element from an encrypted document
--! SELECT eql_v2.jsonb_path_query_first(encrypted_document, 'a7cea93975ed8c01f861ccb6bd082784');
--!
--! @see eql_v2.jsonb_path_query_first(jsonb, text)
CREATE FUNCTION eql_v2.jsonb_path_query_first(val eql_v2_encrypted, selector text)
  RETURNS eql_v2_encrypted
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v2.jsonb_path_query_first((val).data, selector);
$$;



------------------------------------------------------------------------------------


--! @brief Get length of encrypted JSONB array
--!
--! Returns the number of elements in an encrypted JSONB array by counting
--! elements in the STE vector ('sv'). The encrypted value must have the
--! array flag ('a') set to true.
--!
--! @param jsonb Encrypted JSONB payload representing an array
--! @return integer Number of elements in the array
--! @throws Exception 'cannot get array length of a non-array' if 'a' flag is missing or not true
--!
--! @note Array flag 'a' must be present and set to true value
--! @see eql_v2.jsonb_array_elements
CREATE FUNCTION eql_v2.jsonb_array_length(val jsonb)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv eql_v2_encrypted[];
    found eql_v2_encrypted[];
  BEGIN

    IF val IS NULL THEN
      RETURN NULL;
    END IF;

    IF eql_v2.is_ste_vec_array(val) THEN
      sv := eql_v2.ste_vec(val);
      RETURN array_length(sv, 1);
    END IF;

    RAISE 'cannot get array length of a non-array';
  END;
$$ LANGUAGE plpgsql;


--! @brief Get array length from encrypted type
--!
--! Overload that accepts encrypted composite type and extracts the
--! JSONB payload before computing array length.
--!
--! @param eql_v2_encrypted Encrypted array value
--! @return integer Number of elements in the array
--! @throws Exception if value is not an array
--!
--! @example
--! -- Get length of encrypted array
--! SELECT eql_v2.jsonb_array_length(encrypted_tags);
--!
--! @see eql_v2.jsonb_array_length(jsonb)
CREATE FUNCTION eql_v2.jsonb_array_length(val eql_v2_encrypted)
  RETURNS integer
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN (
      SELECT eql_v2.jsonb_array_length(val.data)
    );
  END;
$$ LANGUAGE plpgsql;




--! @brief Extract elements from encrypted JSONB array
--!
--! Returns each element of an encrypted JSONB array as a separate row.
--! Each element is returned as an eql_v2_encrypted value with metadata
--! preserved from the parent array.
--!
--! @param jsonb Encrypted JSONB payload representing an array
--! @return SETOF eql_v2_encrypted One row per array element
--! @throws Exception if value is not an array (missing 'a' flag)
--!
--! @note Each element inherits metadata (version, ident) from parent
--! @see eql_v2.jsonb_array_length
--! @see eql_v2.jsonb_array_elements_text
CREATE FUNCTION eql_v2.jsonb_array_elements(val jsonb)
  RETURNS SETOF eql_v2_encrypted
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv eql_v2_encrypted[];
    meta jsonb;
    item jsonb;
  BEGIN

    IF NOT eql_v2.is_ste_vec_array(val) THEN
      RAISE 'cannot extract elements from non-array';
    END IF;

    -- Column identifier and version
    meta := eql_v2.meta_data(val);

    sv := eql_v2.ste_vec(val);

    FOR idx IN 1..array_length(sv, 1) LOOP
      item = sv[idx];
      RETURN NEXT (meta || item)::eql_v2_encrypted;
    END LOOP;

    RETURN;
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract elements from encrypted array type
--!
--! Overload that accepts encrypted composite type and extracts each
--! array element as a separate row.
--!
--! @param eql_v2_encrypted Encrypted array value
--! @return SETOF eql_v2_encrypted One row per array element
--! @throws Exception if value is not an array
--!
--! @example
--! -- Expand encrypted array into rows
--! SELECT * FROM eql_v2.jsonb_array_elements(encrypted_tags);
--!
--! @see eql_v2.jsonb_array_elements(jsonb)
CREATE FUNCTION eql_v2.jsonb_array_elements(val eql_v2_encrypted)
  RETURNS SETOF eql_v2_encrypted
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN QUERY
      SELECT * FROM eql_v2.jsonb_array_elements(val.data);
  END;
$$ LANGUAGE plpgsql;



--! @brief Extract encrypted array elements as ciphertext
--!
--! Returns each element of an encrypted JSONB array as its raw ciphertext
--! value (text representation). Unlike jsonb_array_elements, this returns
--! only the ciphertext 'c' field without metadata.
--!
--! @param jsonb Encrypted JSONB payload representing an array
--! @return SETOF text One ciphertext string per array element
--! @throws Exception if value is not an array (missing 'a' flag)
--!
--! @note Returns ciphertext only, not full encrypted structure
--! @see eql_v2.jsonb_array_elements
CREATE FUNCTION eql_v2.jsonb_array_elements_text(val jsonb)
  RETURNS SETOF text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    sv eql_v2_encrypted[];
    found eql_v2_encrypted[];
  BEGIN
    IF NOT eql_v2.is_ste_vec_array(val) THEN
      RAISE 'cannot extract elements from non-array';
    END IF;

    sv := eql_v2.ste_vec(val);

    FOR idx IN 1..array_length(sv, 1) LOOP
      RETURN NEXT eql_v2.ciphertext(sv[idx]);
    END LOOP;

    RETURN;
  END;
$$ LANGUAGE plpgsql;


--! @brief Extract array elements as ciphertext from encrypted type
--!
--! Overload that accepts encrypted composite type and extracts each
--! array element's ciphertext as text.
--!
--! @param eql_v2_encrypted Encrypted array value
--! @return SETOF text One ciphertext string per array element
--! @throws Exception if value is not an array
--!
--! @example
--! -- Get ciphertext of each array element
--! SELECT * FROM eql_v2.jsonb_array_elements_text(encrypted_tags);
--!
--! @see eql_v2.jsonb_array_elements_text(jsonb)
CREATE FUNCTION eql_v2.jsonb_array_elements_text(val eql_v2_encrypted)
  RETURNS SETOF text
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN QUERY
      SELECT * FROM eql_v2.jsonb_array_elements_text(val.data);
  END;
$$ LANGUAGE plpgsql;


------------------------------------------------------------------------------------

-- \`eql_v2.hmac_256_terms(eql_v2_encrypted)\` was added under #205 as a
-- GIN-indexable {s, hm} aggregate. It's been removed: under the XOR
-- contract each sv element carries exactly one of \`hm\` (bool leaves,
-- array / object roots) or \`oc\` (string / number leaves), and
-- \`hmac_256_terms\` filters out everything without \`hm\` — so containment
-- queries via this index could never match on string / number selectors.
-- The canonical XOR-aware replacement is the typed
-- \`@>(eql_v2_encrypted, eql_v2.stevec_query)\` overload, which inlines
-- to \`eql_v2.to_stevec_query(col)::jsonb @> needle::jsonb\` and engages
-- a functional GIN on \`(eql_v2.to_stevec_query(col)::jsonb) jsonb_path_ops\`.
-- See U-007 / U-008 in \`docs/upgrading/v2.3.md\`.
--! @file encryptindex/functions.sql
--! @brief Configuration lifecycle and column encryption management
--!
--! Provides functions for managing encryption configuration transitions:
--! - Comparing configurations to identify changes
--! - Identifying columns needing encryption
--! - Creating and renaming encrypted columns during initial setup
--! - Tracking encryption progress
--!
--! These functions support the workflow of activating a pending configuration
--! and performing the initial encryption of plaintext columns.


--! @brief Compare two configurations and find differences
--! @internal
--!
--! Returns table/column pairs where configuration differs between two configs.
--! Used to identify which columns need encryption when activating a pending config.
--!
--! @param a jsonb First configuration to compare
--! @param b jsonb Second configuration to compare
--! @return TABLE(table_name text, column_name text) Columns with differing configuration
--!
--! @note Compares configuration structure, not just presence/absence
--! @see eql_v2.select_pending_columns
CREATE FUNCTION eql_v2.diff_config(a JSONB, b JSONB)
	RETURNS TABLE(table_name TEXT, column_name TEXT)
IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    RETURN QUERY
    WITH table_keys AS (
      SELECT jsonb_object_keys(a->'tables') AS key
      UNION
      SELECT jsonb_object_keys(b->'tables') AS key
    ),
    column_keys AS (
      SELECT tk.key AS table_key, jsonb_object_keys(a->'tables'->tk.key) AS column_key
      FROM table_keys tk
      UNION
      SELECT tk.key AS table_key, jsonb_object_keys(b->'tables'->tk.key) AS column_key
      FROM table_keys tk
    )
    SELECT
      ck.table_key AS table_name,
      ck.column_key AS column_name
    FROM
      column_keys ck
    WHERE
      (a->'tables'->ck.table_key->ck.column_key IS DISTINCT FROM b->'tables'->ck.table_key->ck.column_key);
  END;
$$ LANGUAGE plpgsql;


--! @brief Get columns with pending configuration changes
--!
--! Compares 'pending' and 'active' configurations to identify columns that need
--! encryption or re-encryption. Returns columns where configuration differs.
--!
--! @return TABLE(table_name text, column_name text) Columns needing encryption
--! @throws Exception if no pending configuration exists
--!
--! @note Treats missing active config as empty config
--! @see eql_v2.diff_config
--! @see eql_v2.select_target_columns
CREATE FUNCTION eql_v2.select_pending_columns()
	RETURNS TABLE(table_name TEXT, column_name TEXT)
  SET search_path = pg_catalog, extensions, public
AS $$
	DECLARE
		active JSONB;
		pending JSONB;
		config_id BIGINT;
	BEGIN
		SELECT data INTO active FROM eql_v2_configuration WHERE state = 'active';

		-- set default config
    IF active IS NULL THEN
      active := '{}';
    END IF;

		SELECT id, data INTO config_id, pending FROM eql_v2_configuration WHERE state = 'pending';

		-- set default config
		IF config_id IS NULL THEN
			RAISE EXCEPTION 'No pending configuration exists to encrypt';
		END IF;

		RETURN QUERY
		SELECT d.table_name, d.column_name FROM eql_v2.diff_config(active, pending) as d;
	END;
$$ LANGUAGE plpgsql;


--! @brief Map pending columns to their encrypted target columns
--!
--! For each column with pending configuration, identifies the corresponding
--! encrypted column. During initial encryption, target is '{column_name}_encrypted'.
--! Returns NULL for target_column if encrypted column doesn't exist yet.
--!
--! @return TABLE(table_name text, column_name text, target_column text) Column mappings
--!
--! @note Target column is NULL if no column exists matching either 'column_name' or 'column_name_encrypted' with type eql_v2_encrypted
--! @note The LEFT JOIN checks both original and '_encrypted' suffix variations with type verification
--! @see eql_v2.select_pending_columns
--! @see eql_v2.create_encrypted_columns
CREATE FUNCTION eql_v2.select_target_columns()
	RETURNS TABLE(table_name TEXT, column_name TEXT, target_column TEXT)
	STABLE STRICT PARALLEL SAFE
AS $$
  SELECT
    c.table_name,
    c.column_name,
    s.column_name as target_column
  FROM
    eql_v2.select_pending_columns() c
  LEFT JOIN information_schema.columns s ON
    s.table_name = c.table_name AND
    (s.column_name = c.column_name OR s.column_name = c.column_name || '_encrypted') AND
    s.udt_name = 'eql_v2_encrypted';
$$ LANGUAGE sql;


--! @brief Check if database is ready for encryption
--!
--! Verifies that all columns with pending configuration have corresponding
--! encrypted target columns created. Returns true if encryption can proceed.
--!
--! @return boolean True if all pending columns have target encrypted columns
--!
--! @note Returns false if any pending column lacks encrypted column
--! @see eql_v2.select_target_columns
--! @see eql_v2.create_encrypted_columns
CREATE FUNCTION eql_v2.ready_for_encryption()
	RETURNS BOOLEAN
	STABLE STRICT PARALLEL SAFE
AS $$
	SELECT EXISTS (
	  SELECT *
	  FROM eql_v2.select_target_columns() AS c
	  WHERE c.target_column IS NOT NULL);
$$ LANGUAGE sql;


--! @brief Create encrypted columns for initial encryption
--!
--! For each plaintext column with pending configuration that lacks an encrypted
--! target column, creates a new column '{column_name}_encrypted' of type
--! eql_v2_encrypted. This prepares the database schema for initial encryption.
--!
--! @return TABLE(table_name text, column_name text) Created encrypted columns
--!
--! @warning Executes dynamic DDL (ALTER TABLE ADD COLUMN) - modifies database schema
--! @note Only creates columns that don't already exist
--! @see eql_v2.select_target_columns
--! @see eql_v2.rename_encrypted_columns
CREATE FUNCTION eql_v2.create_encrypted_columns()
	RETURNS TABLE(table_name TEXT, column_name TEXT)
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    FOR table_name, column_name IN
      SELECT c.table_name, (c.column_name || '_encrypted') FROM eql_v2.select_target_columns() AS c WHERE c.target_column IS NULL
    LOOP
		  EXECUTE format('ALTER TABLE %I ADD column %I eql_v2_encrypted;', table_name, column_name);
      RETURN NEXT;
    END LOOP;
	END;
$$ LANGUAGE plpgsql;


--! @brief Finalize initial encryption by renaming columns
--!
--! After initial encryption completes, renames columns to complete the transition:
--! - Plaintext column '{column_name}' → '{column_name}_plaintext'
--! - Encrypted column '{column_name}_encrypted' → '{column_name}'
--!
--! This makes the encrypted column the primary column with the original name.
--!
--! @return TABLE(table_name text, column_name text, target_column text) Renamed columns
--!
--! @warning Executes dynamic DDL (ALTER TABLE RENAME COLUMN) - modifies database schema
--! @note Only renames columns where target is '{column_name}_encrypted'
--! @see eql_v2.create_encrypted_columns
CREATE FUNCTION eql_v2.rename_encrypted_columns()
	RETURNS TABLE(table_name TEXT, column_name TEXT, target_column TEXT)
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    FOR table_name, column_name, target_column IN
      SELECT * FROM eql_v2.select_target_columns() as c WHERE c.target_column = c.column_name || '_encrypted'
    LOOP
		  EXECUTE format('ALTER TABLE %I RENAME %I TO %I;', table_name, column_name, column_name || '_plaintext');
		  EXECUTE format('ALTER TABLE %I RENAME %I TO %I;', table_name, target_column, column_name);
      RETURN NEXT;
    END LOOP;
	END;
$$ LANGUAGE plpgsql;


--! @brief Count rows encrypted with active configuration
--! @internal
--!
--! Counts rows in a table where the encrypted column was encrypted using
--! the currently active configuration. Used to track encryption progress.
--!
--! @param table_name text Name of table to check
--! @param column_name text Name of encrypted column to check
--! @return bigint Count of rows encrypted with active configuration
--!
--! @note The 'v' field in encrypted payloads stores the payload version ("2"), not the configuration ID
--! @note Configuration tracking mechanism is implementation-specific
CREATE FUNCTION eql_v2.count_encrypted_with_active_config(table_name TEXT, column_name TEXT)
  RETURNS BIGINT
  SET search_path = pg_catalog, extensions, public
AS $$
DECLARE
  result BIGINT;
BEGIN
	EXECUTE format(
        'SELECT COUNT(%I) FROM %s t WHERE %I->>%L = (SELECT id::TEXT FROM eql_v2_configuration WHERE state = %L)',
        column_name, table_name, column_name, 'v', 'active'
    )
	INTO result;
  	RETURN result;
END;
$$ LANGUAGE plpgsql;



--! @brief Validate presence of ident field in encrypted payload
--! @internal
--!
--! Checks that the encrypted JSONB payload contains the required 'i' (ident) field.
--! The ident field tracks which table and column the encrypted value belongs to.
--!
--! @param jsonb Encrypted payload to validate
--! @return Boolean True if 'i' field is present
--! @throws Exception if 'i' field is missing
--!
--! @note Used in CHECK constraints to ensure payload structure
--! @see eql_v2.check_encrypted
CREATE FUNCTION eql_v2._encrypted_check_i(val jsonb)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF val ? 'i' THEN
      RETURN true;
    END IF;
    RAISE 'Encrypted column missing ident (i) field: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate table and column fields in ident
--! @internal
--!
--! Checks that the 'i' (ident) field contains both 't' (table) and 'c' (column)
--! subfields, which identify the origin of the encrypted value.
--!
--! @param jsonb Encrypted payload to validate
--! @return Boolean True if both 't' and 'c' subfields are present
--! @throws Exception if 't' or 'c' subfields are missing
--!
--! @note Used in CHECK constraints to ensure payload structure
--! @see eql_v2.check_encrypted
CREATE FUNCTION eql_v2._encrypted_check_i_ct(val jsonb)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF (val->'i' ?& array['t', 'c']) THEN
      RETURN true;
    END IF;
    RAISE 'Encrypted column ident (i) missing table (t) or column (c) fields: %', val;
  END;
$$ LANGUAGE plpgsql;

--! @brief Validate version field in encrypted payload
--! @internal
--!
--! Checks that the encrypted payload has version field 'v' set to '2',
--! the current EQL v2 payload version.
--!
--! @param jsonb Encrypted payload to validate
--! @return Boolean True if 'v' field is present and equals '2'
--! @throws Exception if 'v' field is missing or not '2'
--!
--! @note Used in CHECK constraints to ensure payload structure
--! @see eql_v2.check_encrypted
CREATE FUNCTION eql_v2._encrypted_check_v(val jsonb)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF (val ? 'v') THEN

      IF val->>'v' <> '2' THEN
        RAISE 'Expected encrypted column version (v) 2';
        RETURN false;
      END IF;

      RETURN true;
    END IF;
    RAISE 'Encrypted column missing version (v) field: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate ciphertext field in encrypted payload
--! @internal
--!
--! Checks that the encrypted payload carries the required root-level ciphertext
--! envelope. The v2.3 payload schema admits two mutually exclusive top-level
--! shapes (\`docs/reference/schema/eql-payload-v2.3.schema.json\`):
--!
--!   - \`EncryptedPayload\` (scalar) — carries \`c\` at the root.
--!   - \`SteVecPayload\` (jsonb / structured) — carries \`sv\` at the root; the
--!     root document ciphertext lives inside \`sv[0].c\`, so \`c\` is absent at
--!     the root.
--!
--! Either shape satisfies this check. Per-element ciphertext validity on
--! \`sv\` entries is enforced separately by the \`eql_v2.ste_vec_entry\` DOMAIN.
--!
--! @param jsonb Encrypted payload to validate
--! @return Boolean True if either 'c' or 'sv' is present at the root
--! @throws Exception if neither 'c' nor 'sv' is present
--!
--! @note Used in CHECK constraints to ensure payload structure
--! @see eql_v2.check_encrypted
CREATE FUNCTION eql_v2._encrypted_check_c(val jsonb)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF (val ? 'c') OR (val ? 'sv') THEN
      RETURN true;
    END IF;
    RAISE 'Encrypted column missing ciphertext (c) or ste_vec (sv) field: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate complete encrypted payload structure
--!
--! Comprehensive validation function that checks all required fields in an
--! encrypted JSONB payload: version ('v'), ciphertext ('c'), ident ('i'),
--! and ident subfields ('t', 'c').
--!
--! This function is used in CHECK constraints to ensure encrypted column
--! data integrity at the database level.
--!
--! @param jsonb Encrypted payload to validate
--! @return Boolean True if all structure checks pass
--! @throws Exception if any required field is missing or invalid
--!
--! @example
--! -- Add validation constraint to encrypted column
--! ALTER TABLE users ADD CONSTRAINT check_email_encrypted
--!   CHECK (eql_v2.check_encrypted(encrypted_email::jsonb));
--!
--! @see eql_v2._encrypted_check_v
--! @see eql_v2._encrypted_check_c
--! @see eql_v2._encrypted_check_i
--! @see eql_v2._encrypted_check_i_ct
CREATE FUNCTION eql_v2.check_encrypted(val jsonb)
  RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
BEGIN ATOMIC
    RETURN (
      eql_v2._encrypted_check_v(val) AND
      eql_v2._encrypted_check_c(val) AND
      eql_v2._encrypted_check_i(val) AND
      eql_v2._encrypted_check_i_ct(val)
    );
END;


--! @brief Validate encrypted composite type structure
--!
--! Validates an eql_v2_encrypted composite type by checking its underlying
--! JSONB payload. Delegates to eql_v2.check_encrypted(jsonb).
--!
--! @param eql_v2_encrypted Encrypted value to validate
--! @return Boolean True if structure is valid
--! @throws Exception if any required field is missing or invalid
--!
--! @see eql_v2.check_encrypted(jsonb)
CREATE FUNCTION eql_v2.check_encrypted(val eql_v2_encrypted)
  RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
BEGIN ATOMIC
    RETURN eql_v2.check_encrypted(val.data);
END;


-- Aggregate functions for ORE

--! @brief State transition function for min aggregate
--! @internal
--!
--! Returns the smaller of two encrypted values for use in MIN aggregate.
--! Comparison uses ORE index terms without decryption.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return eql_v2_encrypted The smaller of the two values
--!
--! @see eql_v2.min(eql_v2_encrypted)
CREATE FUNCTION eql_v2.min(a eql_v2_encrypted, b eql_v2_encrypted)
  RETURNS eql_v2_encrypted
STRICT
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF a < b THEN
      RETURN a;
    ELSE
      RETURN b;
    END IF;
  END;
$$ LANGUAGE plpgsql;


--! @brief Find minimum encrypted value in a group
--!
--! Aggregate function that returns the minimum encrypted value in a group
--! using ORE index term comparisons without decryption.
--!
--! @param input eql_v2_encrypted Encrypted values to aggregate
--! @return eql_v2_encrypted Minimum value in the group
--!
--! @example
--! -- Find minimum age per department
--! SELECT department, eql_v2.min(encrypted_age)
--! FROM employees
--! GROUP BY department;
--!
--! @note Requires 'ore' index configuration on the column
--! @see eql_v2.min(eql_v2_encrypted, eql_v2_encrypted)
CREATE AGGREGATE eql_v2.min(eql_v2_encrypted)
(
  sfunc = eql_v2.min,
  stype = eql_v2_encrypted
);


--! @brief State transition function for max aggregate
--! @internal
--!
--! Returns the larger of two encrypted values for use in MAX aggregate.
--! Comparison uses ORE index terms without decryption.
--!
--! @param a eql_v2_encrypted First encrypted value
--! @param b eql_v2_encrypted Second encrypted value
--! @return eql_v2_encrypted The larger of the two values
--!
--! @see eql_v2.max(eql_v2_encrypted)
CREATE FUNCTION eql_v2.max(a eql_v2_encrypted, b eql_v2_encrypted)
RETURNS eql_v2_encrypted
STRICT
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF a > b THEN
      RETURN a;
    ELSE
      RETURN b;
    END IF;
  END;
$$ LANGUAGE plpgsql;


--! @brief Find maximum encrypted value in a group
--!
--! Aggregate function that returns the maximum encrypted value in a group
--! using ORE index term comparisons without decryption.
--!
--! @param input eql_v2_encrypted Encrypted values to aggregate
--! @return eql_v2_encrypted Maximum value in the group
--!
--! @example
--! -- Find maximum salary per department
--! SELECT department, eql_v2.max(encrypted_salary)
--! FROM employees
--! GROUP BY department;
--!
--! @note Requires 'ore' index configuration on the column
--! @see eql_v2.max(eql_v2_encrypted, eql_v2_encrypted)
CREATE AGGREGATE eql_v2.max(eql_v2_encrypted)
(
  sfunc = eql_v2.max,
  stype = eql_v2_encrypted
);


--! @file config/indexes.sql
--! @brief Configuration state uniqueness indexes
--!
--! Creates partial unique indexes to enforce that only one configuration
--! can be in 'active', 'pending', or 'encrypting' state at any time.
--! Multiple 'inactive' configurations are allowed.
--!
--! @note Uses partial indexes (WHERE clauses) for efficiency
--! @note Prevents conflicting configurations from being active simultaneously
--! @see config/types.sql for state definitions


--! @brief Unique active configuration constraint
--! @note Only one configuration can be 'active' at once
CREATE UNIQUE INDEX ON public.eql_v2_configuration (state) WHERE state = 'active';

--! @brief Unique pending configuration constraint
--! @note Only one configuration can be 'pending' at once
CREATE UNIQUE INDEX ON public.eql_v2_configuration (state) WHERE state = 'pending';

--! @brief Unique encrypting configuration constraint
--! @note Only one configuration can be 'encrypting' at once
CREATE UNIQUE INDEX ON public.eql_v2_configuration (state) WHERE state = 'encrypting';


--! @brief Add a search index configuration for an encrypted column
--!
--! Configures a searchable encryption index (unique, match, ore, ope, or ste_vec)
--! on an encrypted column. Creates or updates the pending configuration, then
--! migrates and activates it unless migrating flag is set.
--!
--! @param table_name Text Name of the table containing the column
--! @param column_name Text Name of the column to configure
--! @param index_name Text Type of index ('unique', 'match', 'ore', 'ope', 'ste_vec')
--! @param cast_as Text PostgreSQL type for decrypted values (default: 'text')
--! @param opts JSONB Index-specific options (default: '{}')
--! @param migrating Boolean Skip auto-migration if true (default: false)
--! @return JSONB Updated configuration object
--! @throws Exception if index already exists for this column
--! @throws Exception if cast_as is not a valid type
--!
--! @example
--! -- Add unique index for exact-match searches
--! SELECT eql_v2.add_search_config('users', 'email', 'unique');
--!
--! -- Add match index for LIKE searches with custom token length
--! SELECT eql_v2.add_search_config('posts', 'content', 'match', 'text',
--!   '{"token_filters": [{"kind": "downcase"}], "tokenizer": {"kind": "ngram", "token_length": 3}}'
--! );
--!
--! @see eql_v2.add_column
--! @see eql_v2.remove_search_config
CREATE FUNCTION eql_v2.add_search_config(table_name text, column_name text, index_name text, cast_as text DEFAULT 'text', opts jsonb DEFAULT '{}', migrating boolean DEFAULT false)
  RETURNS jsonb

  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    o jsonb;
    _config jsonb;
  BEGIN

    -- set the active config
    SELECT data INTO _config FROM public.eql_v2_configuration WHERE state = 'active' OR state = 'pending' ORDER BY state DESC;

    -- if index exists
    IF _config #> array['tables', table_name, column_name, 'indexes'] ?  index_name THEN
      RAISE EXCEPTION '% index exists for column: % %', index_name, table_name, column_name;
    END IF;

    IF NOT cast_as = ANY('{text, int, small_int, big_int, real, double, boolean, date, jsonb, json, float, decimal, timestamp}') THEN
      RAISE EXCEPTION '% is not a valid cast type', cast_as;
    END IF;

    -- set default config
    SELECT eql_v2.config_default(_config) INTO _config;

    SELECT eql_v2.config_add_table(table_name, _config) INTO _config;

    SELECT eql_v2.config_add_column(table_name, column_name, _config) INTO _config;

    SELECT eql_v2.config_add_cast(table_name, column_name, cast_as, _config) INTO _config;

    -- set default options for index if opts empty
    IF index_name = 'match' AND opts = '{}' THEN
      SELECT eql_v2.config_match_default() INTO opts;
    END IF;

    SELECT eql_v2.config_add_index(table_name, column_name, index_name, opts, _config) INTO _config;

    --  create a new pending record if we don't have one
    INSERT INTO public.eql_v2_configuration (state, data) VALUES ('pending', _config)
    ON CONFLICT (state)
      WHERE state = 'pending'
    DO UPDATE
      SET data = _config;

    IF NOT migrating THEN
      PERFORM eql_v2.migrate_config();
      PERFORM eql_v2.activate_config();
    END IF;

    PERFORM eql_v2.add_encrypted_constraint(table_name, column_name);

    -- exeunt
    RETURN _config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Remove a search index configuration from an encrypted column
--!
--! Removes a previously configured search index from an encrypted column.
--! Updates the pending configuration, then migrates and activates it
--! unless migrating flag is set.
--!
--! @param table_name Text Name of the table containing the column
--! @param column_name Text Name of the column
--! @param index_name Text Type of index to remove
--! @param migrating Boolean Skip auto-migration if true (default: false)
--! @return JSONB Updated configuration object
--! @throws Exception if no active or pending configuration exists
--! @throws Exception if table is not configured
--! @throws Exception if column is not configured
--!
--! @example
--! -- Remove match index from column
--! SELECT eql_v2.remove_search_config('posts', 'content', 'match');
--!
--! @see eql_v2.add_search_config
--! @see eql_v2.modify_search_config
CREATE FUNCTION eql_v2.remove_search_config(table_name text, column_name text, index_name text, migrating boolean DEFAULT false)
  RETURNS jsonb
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    _config jsonb;
  BEGIN

    -- set the active config
    SELECT data INTO _config FROM public.eql_v2_configuration WHERE state = 'active' OR state = 'pending' ORDER BY state DESC;

    -- if no config
    IF _config IS NULL THEN
      RAISE EXCEPTION 'No active or pending configuration exists';
    END IF;

    -- if the table doesn't exist
    IF NOT _config #> array['tables'] ? table_name THEN
      RAISE EXCEPTION 'No configuration exists for table: %', table_name;
    END IF;

    -- if the index does not exist
    -- IF NOT _config->key ? index_name THEN
    IF NOT _config #> array['tables', table_name] ?  column_name THEN
      RAISE EXCEPTION 'No % index exists for column: % %', index_name, table_name, column_name;
    END IF;

    --  create a new pending record if we don't have one
    INSERT INTO public.eql_v2_configuration (state, data) VALUES ('pending', _config)
    ON CONFLICT (state)
      WHERE state = 'pending'
    DO NOTHING;

    -- remove the index
    SELECT _config #- array['tables', table_name, column_name, 'indexes', index_name] INTO _config;

    -- update the config and migrate (even if empty)
    UPDATE public.eql_v2_configuration SET data = _config WHERE state = 'pending';

    IF NOT migrating THEN
      PERFORM eql_v2.migrate_config();
      PERFORM eql_v2.activate_config();
    END IF;

    -- exeunt
    RETURN _config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Modify a search index configuration for an encrypted column
--!
--! Updates an existing search index configuration by removing and re-adding it
--! with new options. Convenience function that combines remove and add operations.
--! If index does not exist, it is added.
--!
--! @param table_name Text Name of the table containing the column
--! @param column_name Text Name of the column
--! @param index_name Text Type of index to modify
--! @param cast_as Text PostgreSQL type for decrypted values (default: 'text')
--! @param opts JSONB New index-specific options (default: '{}')
--! @param migrating Boolean Skip auto-migration if true (default: false)
--! @return JSONB Updated configuration object
--!
--! @example
--! -- Change match index tokenizer settings
--! SELECT eql_v2.modify_search_config('posts', 'content', 'match', 'text',
--!   '{"tokenizer": {"kind": "ngram", "token_length": 4}}'
--! );
--!
--! @see eql_v2.add_search_config
--! @see eql_v2.remove_search_config
CREATE FUNCTION eql_v2.modify_search_config(table_name text, column_name text, index_name text, cast_as text DEFAULT 'text', opts jsonb DEFAULT '{}', migrating boolean DEFAULT false)
  RETURNS jsonb
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    PERFORM eql_v2.remove_search_config(table_name, column_name, index_name, migrating);
    RETURN eql_v2.add_search_config(table_name, column_name, index_name, cast_as, opts, migrating);
  END;
$$ LANGUAGE plpgsql;

--! @brief Migrate pending configuration to encrypting state
--!
--! Transitions the pending configuration to encrypting state, validating that
--! all configured columns have encrypted target columns ready. This is part of
--! the configuration lifecycle: pending → encrypting → active.
--!
--! @return Boolean True if migration succeeds
--! @throws Exception if encryption already in progress
--! @throws Exception if no pending configuration exists
--! @throws Exception if configured columns lack encrypted targets
--!
--! @example
--! -- Manually migrate configuration (normally done automatically)
--! SELECT eql_v2.migrate_config();
--!
--! @see eql_v2.activate_config
--! @see eql_v2.add_column
CREATE FUNCTION eql_v2.migrate_config()
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN

    IF EXISTS (SELECT FROM public.eql_v2_configuration c WHERE c.state = 'encrypting') THEN
      RAISE EXCEPTION 'An encryption is already in progress';
    END IF;

		IF NOT EXISTS (SELECT FROM public.eql_v2_configuration c WHERE c.state = 'pending') THEN
			RAISE EXCEPTION 'No pending configuration exists to encrypt';
		END IF;

    IF NOT eql_v2.ready_for_encryption() THEN
      RAISE EXCEPTION 'Some pending columns do not have an encrypted target';
    END IF;

    UPDATE public.eql_v2_configuration SET state = 'encrypting' WHERE state = 'pending';
		RETURN true;
  END;
$$ LANGUAGE plpgsql;

--! @brief Activate encrypting configuration
--!
--! Transitions the encrypting configuration to active state, making it the
--! current operational configuration. Marks previous active configuration as
--! inactive. Final step in configuration lifecycle: pending → encrypting → active.
--!
--! @return Boolean True if activation succeeds
--! @throws Exception if no encrypting configuration exists to activate
--!
--! @example
--! -- Manually activate configuration (normally done automatically)
--! SELECT eql_v2.activate_config();
--!
--! @see eql_v2.migrate_config
--! @see eql_v2.add_column
CREATE FUNCTION eql_v2.activate_config()
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN

	  IF EXISTS (SELECT FROM public.eql_v2_configuration c WHERE c.state = 'encrypting') THEN
	  	UPDATE public.eql_v2_configuration SET state = 'inactive' WHERE state = 'active';
			UPDATE public.eql_v2_configuration SET state = 'active' WHERE state = 'encrypting';
			RETURN true;
		ELSE
			RAISE EXCEPTION 'No encrypting configuration exists to activate';
		END IF;
  END;
$$ LANGUAGE plpgsql;

--! @brief Discard pending configuration
--!
--! Deletes the pending configuration without applying changes. Use this to
--! abandon configuration changes before they are migrated and activated.
--!
--! @return Boolean True if discard succeeds
--! @throws Exception if no pending configuration exists to discard
--!
--! @example
--! -- Discard uncommitted configuration changes
--! SELECT eql_v2.discard();
--!
--! @see eql_v2.add_column
--! @see eql_v2.add_search_config
CREATE FUNCTION eql_v2.discard()
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
  BEGIN
    IF EXISTS (SELECT FROM public.eql_v2_configuration c WHERE c.state = 'pending') THEN
        DELETE FROM public.eql_v2_configuration WHERE state = 'pending';
      RETURN true;
    ELSE
      RAISE EXCEPTION 'No pending configuration exists to discard';
    END IF;
  END;
$$ LANGUAGE plpgsql;

--! @brief Configure a column for encryption
--!
--! Adds a column to the encryption configuration, making it eligible for
--! encrypted storage and search indexes. Creates or updates pending configuration,
--! adds encrypted constraint, then migrates and activates unless migrating flag is set.
--!
--! @param table_name Text Name of the table containing the column
--! @param column_name Text Name of the column to encrypt
--! @param cast_as Text PostgreSQL type to cast decrypted values (default: 'text')
--! @param migrating Boolean Skip auto-migration if true (default: false)
--! @return JSONB Updated configuration object
--! @throws Exception if column already configured for encryption
--!
--! @example
--! -- Configure email column for encryption
--! SELECT eql_v2.add_column('users', 'email', 'text');
--!
--! -- Configure age column with integer casting
--! SELECT eql_v2.add_column('users', 'age', 'int');
--!
--! @see eql_v2.add_search_config
--! @see eql_v2.remove_column
CREATE FUNCTION eql_v2.add_column(table_name text, column_name text, cast_as text DEFAULT 'text', migrating boolean DEFAULT false)
  RETURNS jsonb
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    key text;
    _config jsonb;
  BEGIN
    -- set the active config
    SELECT data INTO _config FROM public.eql_v2_configuration WHERE state = 'active' OR state = 'pending' ORDER BY state DESC;

    -- set default config
    SELECT eql_v2.config_default(_config) INTO _config;

    -- if index exists
    IF _config #> array['tables', table_name] ?  column_name THEN
      RAISE EXCEPTION 'Config exists for column: % %', table_name, column_name;
    END IF;

    SELECT eql_v2.config_add_table(table_name, _config) INTO _config;

    SELECT eql_v2.config_add_column(table_name, column_name, _config) INTO _config;

    SELECT eql_v2.config_add_cast(table_name, column_name, cast_as, _config) INTO _config;

    --  create a new pending record if we don't have one
    INSERT INTO public.eql_v2_configuration (state, data) VALUES ('pending', _config)
    ON CONFLICT (state)
      WHERE state = 'pending'
    DO UPDATE
      SET data = _config;

    IF NOT migrating THEN
      PERFORM eql_v2.migrate_config();
      PERFORM eql_v2.activate_config();
    END IF;

    PERFORM eql_v2.add_encrypted_constraint(table_name, column_name);

    -- exeunt
    RETURN _config;
  END;
$$ LANGUAGE plpgsql;

--! @brief Remove a column from encryption configuration
--!
--! Removes a column from the encryption configuration, including all associated
--! search indexes. Removes encrypted constraint, updates pending configuration,
--! then migrates and activates unless migrating flag is set.
--!
--! @param table_name Text Name of the table containing the column
--! @param column_name Text Name of the column to remove
--! @param migrating Boolean Skip auto-migration if true (default: false)
--! @return JSONB Updated configuration object
--! @throws Exception if no active or pending configuration exists
--! @throws Exception if table is not configured
--! @throws Exception if column is not configured
--!
--! @example
--! -- Remove email column from encryption
--! SELECT eql_v2.remove_column('users', 'email');
--!
--! @see eql_v2.add_column
--! @see eql_v2.remove_search_config
CREATE FUNCTION eql_v2.remove_column(table_name text, column_name text, migrating boolean DEFAULT false)
  RETURNS jsonb
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    key text;
    _config jsonb;
  BEGIN
     -- set the active config
    SELECT data INTO _config FROM public.eql_v2_configuration WHERE state = 'active' OR state = 'pending' ORDER BY state DESC;

    -- if no config
    IF _config IS NULL THEN
      RAISE EXCEPTION 'No active or pending configuration exists';
    END IF;

    -- if the table doesn't exist
    IF NOT _config #> array['tables'] ? table_name THEN
      RAISE EXCEPTION 'No configuration exists for table: %', table_name;
    END IF;

    -- if the column does not exist
    IF NOT _config #> array['tables', table_name] ?  column_name THEN
      RAISE EXCEPTION 'No configuration exists for column: % %', table_name, column_name;
    END IF;

    --  create a new pending record if we don't have one
    INSERT INTO public.eql_v2_configuration (state, data) VALUES ('pending', _config)
    ON CONFLICT (state)
      WHERE state = 'pending'
    DO NOTHING;

    -- remove the column
    SELECT _config #- array['tables', table_name, column_name] INTO _config;

    -- if table  is now empty, remove the table
    IF _config #> array['tables', table_name] = '{}' THEN
      SELECT _config #- array['tables', table_name] INTO _config;
    END IF;

    PERFORM eql_v2.remove_encrypted_constraint(table_name, column_name);

    -- update the config (even if empty) and activate
    UPDATE public.eql_v2_configuration SET data = _config WHERE state = 'pending';

    IF NOT migrating THEN
      -- For empty configs, skip migration validation and directly activate
      IF _config #> array['tables'] = '{}' THEN
        UPDATE public.eql_v2_configuration SET state = 'inactive' WHERE state = 'active';
        UPDATE public.eql_v2_configuration SET state = 'active' WHERE state = 'pending';
      ELSE
        PERFORM eql_v2.migrate_config();
        PERFORM eql_v2.activate_config();
      END IF;
    END IF;

    -- exeunt
    RETURN _config;

  END;
$$ LANGUAGE plpgsql;

--! @brief Reload configuration from CipherStash Proxy
--!
--! Placeholder function for reloading configuration from the CipherStash Proxy.
--! Currently returns NULL without side effects.
--!
--! @return Void
--!
--! @note This function may be used for configuration synchronization in future versions
CREATE FUNCTION eql_v2.reload_config()
  RETURNS void
LANGUAGE sql STRICT PARALLEL SAFE
BEGIN ATOMIC
  RETURN NULL;
END;

--! @brief Query encryption configuration in tabular format
--!
--! Returns the active encryption configuration as a table for easier querying
--! and filtering. Shows all configured tables, columns, cast types, and indexes.
--!
--! @return TABLE Contains configuration state, relation name, column name, cast type, and indexes
--!
--! @example
--! -- View all encrypted columns
--! SELECT * FROM eql_v2.config();
--!
--! -- Find all columns with match indexes
--! SELECT relation, col_name FROM eql_v2.config()
--! WHERE indexes ? 'match';
--!
--! @see eql_v2.add_column
--! @see eql_v2.add_search_config
CREATE FUNCTION eql_v2.config() RETURNS TABLE (
    state eql_v2_configuration_state,
    relation text,
    col_name text,
    decrypts_as text,
    indexes jsonb
)
  SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
    RETURN QUERY
      WITH tables AS (
          SELECT cfg.state, tables.key AS table, tables.value AS tbl_config
          FROM public.eql_v2_configuration cfg, jsonb_each(data->'tables') tables
          WHERE cfg.data->>'v' = '1'
      )
      SELECT
          tables.state,
          tables.table,
          column_config.key,
          COALESCE(column_config.value->>'plaintext_type', column_config.value->>'cast_as'),
          column_config.value->'indexes'
      FROM tables, jsonb_each(tables.tbl_config) column_config;
END;
$$ LANGUAGE plpgsql;

--! @file config/constraints.sql
--! @brief Configuration validation functions and constraints
--!
--! Provides CHECK constraint functions to validate encryption configuration structure.
--! Ensures configurations have required fields (version, tables) and valid values
--! for index types and cast types before being stored.
--!
--! @see config/tables.sql where constraints are applied


--! @brief Extract index type names from configuration
--! @internal
--!
--! Helper function that extracts all index type names from the configuration's
--! 'indexes' sections across all tables and columns.
--!
--! @param jsonb Configuration data to extract from
--! @return SETOF text Index type names (e.g., 'match', 'ore', 'unique', 'ste_vec')
--!
--! @note Used by config_check_indexes for validation
--! @see eql_v2.config_check_indexes
CREATE FUNCTION eql_v2.config_get_indexes(val jsonb)
    RETURNS SETOF text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
BEGIN ATOMIC
	SELECT jsonb_object_keys(jsonb_path_query(val,'$.tables.*.*.indexes'));
END;


--! @brief Validate index types in configuration
--! @internal
--!
--! Checks that all index types specified in the configuration are valid.
--! Valid index types are: match, ore, ope, unique, ste_vec.
--!
--! @param jsonb Configuration data to validate
--! @return boolean True if all index types are valid
--! @throws Exception if any invalid index type found
--!
--! @note Used in CHECK constraint on eql_v2_configuration table
--! @see eql_v2.config_get_indexes
CREATE FUNCTION eql_v2.config_check_indexes(val jsonb)
  RETURNS BOOLEAN
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN

    IF (SELECT EXISTS (SELECT eql_v2.config_get_indexes(val))) THEN
      IF (SELECT bool_and(index = ANY('{match, ore, ope, unique, ste_vec}')) FROM eql_v2.config_get_indexes(val) AS index) THEN
        RETURN true;
      END IF;
      RAISE 'Configuration has an invalid index (%). Index should be one of {match, ore, ope, unique, ste_vec}', val;
    END IF;
    RETURN true;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate cast types in configuration
--! @internal
--!
--! Checks that all 'cast_as' and 'plaintext_type' types specified in the configuration are valid.
--! Valid cast types are: text, int, small_int, big_int, real, double, boolean, date, jsonb, json, float, decimal, timestamp.
--!
--! @param jsonb Configuration data to validate
--! @return boolean True if all cast types are valid or no cast types specified
--! @throws Exception if any invalid cast type found
--!
--! @note Used in CHECK constraint on eql_v2_configuration table
--! @note Empty configurations (no cast_as/plaintext_type fields) are valid
--! @note Cast type names are EQL's internal representations, not PostgreSQL native types
--! @note 'plaintext_type' is accepted as a canonical alias for 'cast_as'
CREATE FUNCTION eql_v2.config_check_cast(val jsonb)
  RETURNS BOOLEAN
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    _valid_types text[] := '{text, int, small_int, big_int, real, double, boolean, date, jsonb, json, float, decimal, timestamp}';
	BEGIN
    -- Validate cast_as fields
    IF EXISTS (SELECT jsonb_array_elements_text(jsonb_path_query_array(val, '$.tables.*.*.cast_as'))) THEN
      IF NOT (SELECT bool_and(cast_as = ANY(_valid_types))
          FROM (SELECT jsonb_array_elements_text(jsonb_path_query_array(val, '$.tables.*.*.cast_as')) AS cast_as) casts) THEN
        RAISE 'Configuration has an invalid cast_as (%). Cast should be one of %', val, _valid_types;
      END IF;
    END IF;

    -- Validate plaintext_type fields (canonical alias for cast_as)
    IF EXISTS (SELECT jsonb_array_elements_text(jsonb_path_query_array(val, '$.tables.*.*.plaintext_type'))) THEN
      IF NOT (SELECT bool_and(pt = ANY(_valid_types))
          FROM (SELECT jsonb_array_elements_text(jsonb_path_query_array(val, '$.tables.*.*.plaintext_type')) AS pt) types) THEN
        RAISE 'Configuration has an invalid plaintext_type (%). Type should be one of %', val, _valid_types;
      END IF;
    END IF;

    RETURN true;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate tables field presence
--! @internal
--!
--! Ensures the configuration has a 'tables' field, which is required
--! to specify which database tables contain encrypted columns.
--!
--! @param jsonb Configuration data to validate
--! @return boolean True if 'tables' field exists
--! @throws Exception if 'tables' field is missing
--!
--! @note Used in CHECK constraint on eql_v2_configuration table
CREATE FUNCTION eql_v2.config_check_tables(val jsonb)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF (val ? 'tables') THEN
      RETURN true;
    END IF;
    RAISE 'Configuration missing tables (tables) field: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate version field presence
--! @internal
--!
--! Ensures the configuration has a 'v' (version) field, which tracks
--! the configuration format version.
--!
--! @param jsonb Configuration data to validate
--! @return boolean True if 'v' field exists
--! @throws Exception if 'v' field is missing
--!
--! @note Used in CHECK constraint on eql_v2_configuration table
CREATE FUNCTION eql_v2.config_check_version(val jsonb)
  RETURNS boolean
  SET search_path = pg_catalog, extensions, public
AS $$
	BEGIN
    IF (val ? 'v') THEN
      RETURN true;
    END IF;
    RAISE 'Configuration missing version (v) field: %', val;
  END;
$$ LANGUAGE plpgsql;


--! @brief Validate ste_vec index mode option
--! @internal
--!
--! Checks that the optional \`mode\` field on \`ste_vec\` index configurations is
--! one of the recognised values. Valid modes are: standard, compat.
--! Configurations without a \`mode\` field (the default) pass unconditionally.
--!
--! @param jsonb Configuration data to validate
--! @return boolean True if every ste_vec mode is valid, or none are set
--! @throws Exception if any ste_vec.mode value is not in the allowed set
--!
--! @note Used in CHECK constraint on eql_v2_configuration table
--! @note Mode is optional — only configurations that set it are validated
CREATE FUNCTION eql_v2.config_check_ste_vec_mode(val jsonb)
  RETURNS BOOLEAN
  IMMUTABLE STRICT PARALLEL SAFE
  SET search_path = pg_catalog, extensions, public
AS $$
  DECLARE
    _valid_modes text[] := '{standard, compat}';
  BEGIN
    IF EXISTS (SELECT jsonb_array_elements_text(jsonb_path_query_array(val, '$.tables.*.*.indexes.ste_vec.mode'))) THEN
      IF NOT (SELECT bool_and(mode = ANY(_valid_modes))
          FROM (SELECT jsonb_array_elements_text(jsonb_path_query_array(val, '$.tables.*.*.indexes.ste_vec.mode')) AS mode) modes) THEN
        RAISE 'Configuration has an invalid ste_vec mode (%). Mode should be one of %', val, _valid_modes;
      END IF;
    END IF;
    RETURN true;
  END;
$$ LANGUAGE plpgsql;


--! @brief Drop existing data validation constraint if present
--! @note Allows constraint to be recreated during upgrades
ALTER TABLE public.eql_v2_configuration DROP CONSTRAINT IF EXISTS eql_v2_configuration_data_check;


--! @brief Comprehensive configuration data validation
--!
--! CHECK constraint that validates all aspects of configuration data:
--! - Version field presence
--! - Tables field presence
--! - Valid cast_as types
--! - Valid index types
--! - Valid ste_vec mode (when set)
--!
--! @note Combines all config_check_* validation functions
--! @see eql_v2.config_check_version
--! @see eql_v2.config_check_tables
--! @see eql_v2.config_check_cast
--! @see eql_v2.config_check_indexes
--! @see eql_v2.config_check_ste_vec_mode
ALTER TABLE public.eql_v2_configuration
  ADD CONSTRAINT eql_v2_configuration_data_check CHECK (
    eql_v2.config_check_version(data) AND
    eql_v2.config_check_tables(data) AND
    eql_v2.config_check_cast(data) AND
    eql_v2.config_check_indexes(data) AND
    eql_v2.config_check_ste_vec_mode(data)
);


--! @file pin_search_path.sql
--! @brief Post-install: pin search_path on every eql_v2.* function
--!
--! This file is appended verbatim by \`tasks/build.sh\` to the end of every
--! release variant (main, supabase, protect/stack), AFTER all \`src/**/*.sql\`
--! files have been concatenated. It lives outside \`src/\` so it stays out of
--! the dependency graph entirely — each variant has a different leaf set
--! (supabase excludes \`**/*operator_class.sql\`; protect excludes \`src/config/*\`
--! and \`src/encryptindex/*\`), and threading REQUIREs to be ordered last in
--! every variant simultaneously is fragile.
--!
--! Iterates over functions in the \`eql_v2\` schema and applies a fixed
--! \`search_path\` via \`ALTER FUNCTION ... SET search_path = ...\`. This is the
--! only way to satisfy Supabase splinter's \`function_search_path_mutable\`
--! lint, which checks \`pg_proc.proconfig\` directly.
--!
--! @note A SET clause disables PostgreSQL's SQL-function inlining (see
--!       inline_function() in src/backend/optimizer/util/clauses.c). For most
--!       eql_v2 helpers this is irrelevant. The exceptions are wrappers that
--!       must inline to expose \`eql_v2.jsonb_array(col) @> ...\` to the planner
--!       so the GIN index on \`jsonb_array(e)\` can be matched. Those are
--!       deliberately skipped here and allowlisted in \`tasks/test/splinter.sh\`.
--!
--! @see tasks/test/splinter.sh
--! @see tasks/build.sh

DO $$
DECLARE
  fn_oid oid;
  inline_critical_oids oid[];
  enc_oid oid;
  jsonb_oid oid;
  text_oid oid;
  entry_oid oid;
BEGIN
  -- Resolve type oids without depending on caller search_path. The encrypted
  -- composite type is created in \`public\`; jsonb / text are in \`pg_catalog\`;
  -- the ste_vec_entry DOMAIN lives in \`eql_v2\`.
  SELECT t.oid INTO enc_oid
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'public' AND t.typname = 'eql_v2_encrypted';

  IF enc_oid IS NULL THEN
    RAISE EXCEPTION 'pin_search_path: type public.eql_v2_encrypted not found — '
      'this script must run after all EQL src/**/*.sql files have been loaded';
  END IF;

  SELECT t.oid INTO jsonb_oid
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'pg_catalog' AND t.typname = 'jsonb';

  IF jsonb_oid IS NULL THEN
    RAISE EXCEPTION 'pin_search_path: type pg_catalog.jsonb not found';
  END IF;

  SELECT t.oid INTO text_oid
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'pg_catalog' AND t.typname = 'text';

  IF text_oid IS NULL THEN
    RAISE EXCEPTION 'pin_search_path: type pg_catalog.text not found';
  END IF;

  SELECT t.oid INTO entry_oid
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'eql_v2' AND t.typname = 'ste_vec_entry';

  IF entry_oid IS NULL THEN
    RAISE EXCEPTION 'pin_search_path: type eql_v2.ste_vec_entry not found';
  END IF;

  -- Wrappers that must remain inlinable for functional-index matching.
  -- Verified empirically: with SET, EXPLAIN drops to Seq Scan; without,
  -- it uses Bitmap Index Scan / Index Scan.
  --
  -- Phase 1 operator inlining (#193): \`=\`, \`<>\`, \`~~\`, \`~~*\`, \`@>\`, \`<@\`
  -- on \`eql_v2_encrypted\` and the cross-type (encrypted, jsonb) /
  -- (jsonb, encrypted) overloads emitted by ORMs that bind parameters
  -- as jsonb (Drizzle, PostgREST, encryptedSupabase). The implementation
  -- functions reduce to \`extractor(a) op extractor(b)\` and must inline
  -- to match the documented functional indexes
  -- (\`eql_v2.hmac_256(col)\`, \`eql_v2.bloom_filter(col)\`,
  -- \`eql_v2.ste_vec(col)\`).
  --
  -- For \`~~\` / \`~~*\` the planner must inline two layers — the operator
  -- function \`eql_v2."~~"\` and the helper \`eql_v2.like\` / \`eql_v2.ilike\`
  -- — to reach the canonical \`eql_v2.bloom_filter(a) @> eql_v2.bloom_filter(b)\`
  -- form that the documented functional index matches. The helpers are
  -- allowlisted alongside the operator wrappers below; pinning either
  -- layer breaks the chain and reverts to Seq Scan.
  --
  -- Note: pg_proc.proargtypes is an oidvector with 0-based bounds, so we
  -- compare elements individually rather than using array equality (which
  -- requires matching bounds, not just contents).
  SELECT pg_catalog.array_agg(p.oid) INTO inline_critical_oids
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'eql_v2'
    AND (
      -- Same-type (encrypted, encrypted) operators that must inline.
      -- \`like\`/\`ilike\` are the SQL helpers that \`~~\`/\`~~*\` delegate to;
      -- both layers must inline to reach \`bloom_filter(a) @> bloom_filter(b)\`.
      -- \`<\`, \`<=\`, \`>\`, \`>=\` inline to \`ore_block_u64_8_256(a) op
      -- ore_block_u64_8_256(b)\`; they must reach the functional ORE index
      -- expression \`eql_v2.ore_block_u64_8_256(col)\` for bare range
      -- queries to engage Index Scan.
      (p.pronargs = 2
        AND p.proname IN ('=', '<>', '<', '<=', '>', '>=',
                          '~~', '~~*', '@>', '<@',
                          'jsonb_contains', 'jsonb_contained_by',
                          'like', 'ilike')
        AND p.proargtypes[0] = enc_oid AND p.proargtypes[1] = enc_oid)
      -- Cross-type (encrypted, jsonb).
      OR (p.pronargs = 2
        AND p.proname IN ('=', '<>', '<', '<=', '>', '>=',
                          '~~', '~~*',
                          'jsonb_contains', 'jsonb_contained_by')
        AND p.proargtypes[0] = enc_oid AND p.proargtypes[1] = jsonb_oid)
      -- Cross-type (jsonb, encrypted).
      OR (p.pronargs = 2
        AND p.proname IN ('=', '<>', '<', '<=', '>', '>=',
                          '~~', '~~*',
                          'jsonb_contains', 'jsonb_contained_by')
        AND p.proargtypes[0] = jsonb_oid AND p.proargtypes[1] = enc_oid)
      -- Root-level HMAC extractor (#205): all 1-arg overloads are now
      -- inlinable SQL. Must stay unpinned so the planner can fold extractor
      -- calls inside the inlined equality operator bodies into the calling
      -- query, preserving the functional-index match.
      OR (p.pronargs = 1
        AND p.proname = 'hmac_256'
        AND (p.proargtypes[0] = enc_oid OR p.proargtypes[0] = jsonb_oid))
      -- Field-level JSONB extractors (#205): inlinable SQL replacements for
      -- the previous plpgsql bodies. Inlining lets the planner fold the
      -- \`jsonb_array_elements(...) WHERE elem->>'s' = selector\` body into
      -- the calling query, eliminating per-row function call overhead on
      -- large ste_vec scans.
      OR (p.pronargs = 2
        AND p.proname IN ('jsonb_path_query',
                          'jsonb_path_query_first',
                          'jsonb_path_exists'))
      -- Inner ORE-block comparison helpers backing the \`<\`, \`<=\`, \`>\`, \`>=\`
      -- operators on \`eql_v2.ore_block_u64_8_256\`. The outer operators on
      -- \`eql_v2_encrypted\` inline to \`ore_block(a) <op> ore_block(b)\`, and
      -- PG only carries the inlined form through to index matching if the
      -- inner operator function is also inlinable (no SET, IMMUTABLE).
      -- Pinning these would prevent the planner from structurally matching
      -- predicates against a functional \`eql_v2.ore_block_u64_8_256(col)\`
      -- index. The inner functions are deterministic comparisons of
      -- composite type bytes, declared IMMUTABLE STRICT PARALLEL SAFE.
      OR (p.pronargs = 2
        AND p.proname IN ('ore_block_u64_8_256_eq', 'ore_block_u64_8_256_neq',
                          'ore_block_u64_8_256_lt', 'ore_block_u64_8_256_lte',
                          'ore_block_u64_8_256_gt', 'ore_block_u64_8_256_gte'))
      -- Hash operator class FUNCTION 1: called once per row by HashAggregate,
      -- hash joins, DISTINCT. Inlinable SQL avoids the per-row plpgsql
      -- interpreter overhead — without this, \`GROUP BY value\` on
      -- \`eql_v2_encrypted\` at 1M rows degrades super-linearly because the
      -- plpgsql cost compounds with HashAggregate work_mem spillage.
      OR (p.pronargs = 1
        AND p.proname = 'hash_encrypted'
        AND p.proargtypes[0] = enc_oid)
      -- Consolidated ORE-CLLW extractor (U-006). Inlinable SQL — pinning
      -- would silently undo it and prevent the planner from folding
      -- \`eql_v2.ore_cllw(col)\` calls into the calling query. The
      -- \`compare_ore_cllw_term\` comparator stays plpgsql by design (per-byte
      -- protocol can't be expressed as a single inlinable SELECT), so it is
      -- NOT on this list. The (jsonb) form is a RHS-parameter helper for
      -- comparisons against literal jsonb; the (eql_v2.ste_vec_entry) form
      -- is the typed extractor for the result of \`col -> '<selector>'\`.
      OR (p.pronargs = 1
        AND p.proname IN ('ore_cllw', 'has_ore_cllw')
        AND (p.proargtypes[0] = jsonb_oid OR p.proargtypes[0] = entry_oid))
      -- Typed HMAC extractor on a ste_vec entry (#219 strict separation).
      -- Same rationale as \`ore_cllw(ste_vec_entry)\` — must inline so
      -- \`eql_v2.hmac_256(col -> 'sel')\` folds into the calling query and
      -- matches a functional hash index built on the same expression.
      OR (p.pronargs = 1
        AND p.proname IN ('hmac_256', 'has_hmac_256', 'selector')
        AND p.proargtypes[0] = entry_oid)
      -- \`eql_v2.ste_vec_entry × eql_v2.ste_vec_entry\` operators (#219).
      -- Inline to \`hmac_256(a) = hmac_256(b)\` (equality) or
      -- \`ore_cllw(a) <op> ore_cllw(b)\` (ordering); both chains must remain
      -- unpinned for functional-index match through extractor form.
      OR (p.pronargs = 2
        AND p.proname IN ('=', '<>', '<', '<=', '>', '>=',
                          'eq', 'neq', 'lt', 'lte', 'gt', 'gte')
        AND p.proargtypes[0] = entry_oid AND p.proargtypes[1] = entry_oid)
      -- Inner ORE-CLLW comparison helpers backing the \`<\`, \`<=\`, \`=\`,
      -- \`>=\`, \`>\`, \`<>\` operators on \`eql_v2.ore_cllw\` (the composite
      -- type, registered via \`eql_v2.ore_cllw_ops\` opclass — #221). Same
      -- precedent as the \`ore_block_u64_8_256_*\` helpers above: PG only
      -- carries the inlined operator wrapper through to functional-index
      -- match if the inner backing function is also inlinable. Pinning
      -- these would break the index match for \`ORDER BY eql_v2.ore_cllw
      -- (value -> '<selector>'::text)\` and the matching \`WHERE\` form.
      OR (p.pronargs = 2
        AND p.proname IN ('ore_cllw_eq', 'ore_cllw_neq',
                          'ore_cllw_lt', 'ore_cllw_lte',
                          'ore_cllw_gt', 'ore_cllw_gte'))
      -- \`->\` selector lookup: inlinable SQL post the type flip
      -- (returns \`eql_v2.ste_vec_entry\`). Must stay unpinned so the
      -- planner can fold \`col -> '<selector>'\` into the calling query
      -- — without this, the chained recipe
      -- \`WHERE col -> 'sel' = $1::ste_vec_entry\` would not match a
      -- functional hash index on \`eql_v2.eq_term(col -> 'sel')\`.
      OR (p.proname = '->'
        AND p.pronargs = 2
        AND p.proargtypes[0] = enc_oid
        AND (p.proargtypes[1] = text_oid
             OR p.proargtypes[1] = enc_oid
             OR p.proargtypes[1] = (SELECT t.oid FROM pg_catalog.pg_type t
                                     JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                                     WHERE n.nspname = 'pg_catalog' AND t.typname = 'int4')))
      -- XOR-aware equality term extractor on a ste_vec entry. Must
      -- inline so \`eql_v2.eq_term(col -> 'sel')\` folds into the
      -- calling query and matches a functional hash index built on
      -- the same expression.
      OR (p.pronargs = 1
        AND p.proname = 'eq_term'
        AND p.proargtypes[0] = entry_oid)
      -- Type-safe \`@>\` / \`<@\` overloads with typed needles
      -- (\`stevec_query\`, \`ste_vec_entry\`). Inline to the existing
      -- \`ste_vec_contains\` machinery — must stay unpinned to engage
      -- the GIN index on \`eql_v2.ste_vec(col)\` structurally for
      -- bare-form containment.
      OR (p.pronargs = 2
        AND p.proname IN ('@>', '<@')
        AND p.proargtypes[0] = enc_oid
        AND (p.proargtypes[1] = entry_oid
             OR p.proargtypes[1] = (SELECT t.oid FROM pg_catalog.pg_type t
                                     JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                                     WHERE n.nspname = 'eql_v2' AND t.typname = 'stevec_query')))
      OR (p.pronargs = 2
        AND p.proname IN ('@>', '<@')
        AND p.proargtypes[1] = enc_oid
        AND (p.proargtypes[0] = entry_oid
             OR p.proargtypes[0] = (SELECT t.oid FROM pg_catalog.pg_type t
                                     JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                                     WHERE n.nspname = 'eql_v2' AND t.typname = 'stevec_query')))
    );

  FOR fn_oid IN
    SELECT p.oid
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'eql_v2'
      -- Only normal functions ('f') and window functions ('w') accept
      -- ALTER FUNCTION ... SET. Aggregates ('a') would be rejected by
      -- ALTER ROUTINE/FUNCTION, and procedures ('p') would need ALTER
      -- PROCEDURE. The 3 affected aggregates (min, max, grouped_value)
      -- are allowlisted in splinter.
      AND p.prokind IN ('f', 'w')
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.unnest(coalesce(p.proconfig, '{}'::text[])) c
        WHERE c LIKE 'search_path=%'
      )
      AND NOT (p.oid = ANY (coalesce(inline_critical_oids, '{}'::oid[])))
  LOOP
    -- oid::regprocedure renders as \`schema.name(argtype, argtype)\` and is a
    -- valid target for ALTER FUNCTION regardless of caller search_path.
    EXECUTE pg_catalog.format(
      'ALTER FUNCTION %s SET search_path = pg_catalog, extensions, public',
      fn_oid::regprocedure
    );
  END LOOP;
END $$;
`;
