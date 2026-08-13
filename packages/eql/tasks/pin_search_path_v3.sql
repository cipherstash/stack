--! @file pin_search_path_v3.sql
--! @brief Post-install: pin search_path on every eql_v3.* function.
--!
--! Appended verbatim by `tasks/build.sh` to the end of the v3-only release
--! artifact, AFTER all src/v3/**/*.sql files have been concatenated. It lives
--! outside src/ so it stays out of the dependency graph.
--!
--! Iterates over functions in the `eql_v3` and `eql_v3_internal` schemas and
--! applies a fixed `search_path` via `ALTER FUNCTION ... SET search_path = ...`,
--! satisfying Supabase splinter's `function_search_path_mutable` lint.
--!
--! @note A SET clause disables SQL-function inlining. The inline-critical SEM
--!       helpers (ore_block_256_*, ope_cllw, hmac_256, bloom_filter over
--!       jsonb) and the encrypted-domain family (recognised structurally,
--!       including public user-column domains) are deliberately left
--!       unpinned.
--! @see tasks/test/splinter.sh
--! @see tasks/build.sh

DO $$
DECLARE
  fn_oid oid;
  inline_critical_oids oid[];
  jsonb_oid oid;
BEGIN
  SELECT t.oid INTO jsonb_oid
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'pg_catalog' AND t.typname = 'jsonb';

  IF jsonb_oid IS NULL THEN
    RAISE EXCEPTION 'pin_search_path_v3: type pg_catalog.jsonb not found';
  END IF;

  -- eql_v3 SEM index-term functions that must stay inlinable for
  -- functional-index matching (no SET, IMMUTABLE). Mirrors the eql_v3 clause
  -- in the legacy combined pin_search_path.sql.
  SELECT pg_catalog.array_agg(p.oid) INTO inline_critical_oids
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = ANY(eql_v3_internal.owned_schemas())
    AND (
      (p.pronargs = 2
        AND p.proname IN ('ore_block_256_eq', 'ore_block_256_neq',
                          'ore_block_256_lt', 'ore_block_256_lte',
                          'ore_block_256_gt', 'ore_block_256_gte'))
      -- The CLLW-OPE surface is the extractor alone: eql_v3_internal.ope_cllw is a
      -- domain over bytea (native comparison operators and btree opclass),
      -- so there are no ope-specific comparison functions to keep inlinable.
      OR (p.pronargs = 1
        AND p.proname = 'ope_cllw'
        AND p.proargtypes[0] = jsonb_oid)
      OR (p.pronargs = 1
        AND p.proname = 'hmac_256'
        AND p.proargtypes[0] = jsonb_oid)
      OR (p.pronargs = 1
        AND p.proname = 'bloom_filter'
        AND p.proargtypes[0] = jsonb_oid)
    );

  FOR fn_oid IN
    SELECT p.oid
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = ANY(eql_v3_internal.owned_schemas())
      AND p.prokind IN ('f', 'w')
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.unnest(coalesce(p.proconfig, '{}'::text[])) c
        WHERE c LIKE 'search_path=%'
      )
      AND NOT (p.oid = ANY (coalesce(inline_critical_oids, '{}'::oid[])))
      -- Encrypted-domain family — structural skip: LANGUAGE sql, IMMUTABLE,
      -- taking >=1 argument typed as a jsonb-backed DOMAIN. User-column
      -- domains live in public; implementation-only domains live in EQL-owned
      -- schemas.
      AND NOT (
        p.prolang = (SELECT l.oid FROM pg_catalog.pg_language l
                     WHERE l.lanname = 'sql')
        AND p.provolatile = 'i'
        AND EXISTS (
          SELECT 1
          FROM pg_catalog.unnest(p.proargtypes::oid[]) AS arg(typ)
          JOIN pg_catalog.pg_type dt ON dt.oid = arg.typ
          JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
          WHERE dt.typtype = 'd'
            AND dt.typbasetype = jsonb_oid
            AND (
              dn.nspname = 'public'
              OR dn.nspname = ANY(eql_v3_internal.owned_schemas())
            )
        )
      )
      -- Comment-marker fallback for hand-written inline-critical extension
      -- functions that take no domain argument.
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_description d
        WHERE d.objoid = p.oid
          AND d.classoid = 'pg_catalog.pg_proc'::regclass
          AND d.description LIKE 'eql-inline-critical%'
      )
  LOOP
    EXECUTE pg_catalog.format(
      'ALTER FUNCTION %s SET search_path = pg_catalog, extensions, public',
      fn_oid::regprocedure
    );
  END LOOP;
END $$;
