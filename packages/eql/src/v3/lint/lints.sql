-- REQUIRE: src/v3/schema.sql

--! @brief EQL lint: detect non-inlinable operator implementation functions
--!
--! Returns one row per violation found in the installed `eql_v3` surface. The
--! Postgres planner can only inline a function during index matching when:
--!
--!   * `LANGUAGE sql` (plpgsql / C / etc. cannot be inlined)
--!   * `IMMUTABLE` or `STABLE` volatility (VOLATILE cannot be inlined into
--!     index expressions)
--!   * No `SET` clauses (e.g. `SET search_path = ...`)
--!   * Not `SECURITY DEFINER`
--!   * Single-statement SELECT body
--!
--! @note The single-statement SELECT body condition is **not yet checked** by
--! this lint. A `LANGUAGE sql` function with a multi-statement body, a CTE,
--! or any pre-SELECT statement will pass all four implemented checks while
--! remaining non-inlinable. Implementing the check requires walking `prosrc`
--! (or `pg_get_functiondef`); tracked as a follow-up.
--!
--! Operators on `eql_v3` types (the jsonb-backed encrypted-domain families and
--! the SEM index-term type `eql_v3_internal.ore_block_256`) whose
--! implementation functions fail any of these rules silently fall back to seq
--! scan when the documented functional indexes (`eql_v3.eq_term(col)`,
--! `eql_v3.ord_term(col)`) are in place. This lint surfaces every such case.
--!
--! Severity:
--!   `error`   — fixable, blocks index matching, ship-blocking.
--!   `warning` — likely-fixable, may not block matching but signals intent.
--!   `info`    — observational; useful for review, not a defect on its own.
--!
--! Categories:
--!   `inlinability_language`   — implementation function isn't `LANGUAGE sql`.
--!   `inlinability_volatility` — implementation function is VOLATILE.
--!   `inlinability_set_clause` — implementation function has a `SET` clause.
--!   `inlinability_secdef`     — implementation function is `SECURITY DEFINER`.
--!   `inlinability_transitive` — implementation function is itself inlinable
--!                                but its body invokes a non-inlinable function
--!                                (depth 1; the planner can't peek through
--!                                that boundary).
--!   `blocker_language`        — encrypted-domain blocker is not LANGUAGE
--!                                plpgsql. The planner can inline / elide a
--!                                LANGUAGE sql body when the result is
--!                                provably unused, silently bypassing the
--!                                RAISE that the blocker exists to perform.
--!   `blocker_strict`          — encrypted-domain blocker is STRICT.
--!                                PostgreSQL skips the body and returns NULL
--!                                on NULL arguments, silently bypassing the
--!                                RAISE.
--!   `domain_over_domain`      — an `eql_v3` encrypted domain is derived from
--!                                another encrypted domain rather than jsonb.
--!                                Operators resolve against the ultimate base
--!                                type, so the derived domain does not
--!                                inherit the base domain's blocker surface.
--!   `domain_opclass`          — an operator class is declared FOR TYPE on an
--!                                `eql_v3` encrypted domain. Opclasses on
--!                                domains bypass operator resolution; use a
--!                                functional index on the extractor instead.
--!   `schema_placement`        — a naked composite or enum TYPE lives in the
--!                                public `eql_v3` schema. Internal index-term
--!                                types (e.g. `ore_block_256_term`) belong in
--!                                `eql_v3_internal`; a composite/enum in
--!                                `eql_v3` clutters the Supabase Table Builder
--!                                type picker, which the schema split exists to
--!                                prevent. Move it to `eql_v3_internal`.
--!
--! @code{.sql}
--! SELECT severity, category, object_name, message
--!   FROM eql_v3.lints()
--!  WHERE severity = 'error'
--!  ORDER BY category, object_name;
--! @endcode
--!
--! @return SETOF record (severity text, category text, object_name text, message text)
CREATE OR REPLACE FUNCTION eql_v3.lints()
RETURNS TABLE (
  severity text,
  category text,
  object_name text,
  message text
)
LANGUAGE sql STABLE
AS $$
  WITH
  -- User-column encrypted domains now live in public so application tables
  -- survive EQL uninstall. Keep this separate from owned_schemas(): public is
  -- not installer-owned, but its EQL jsonb-backed domains are still the domain
  -- types whose blockers/operator surfaces the lint must understand.
  encrypted_domain_types AS (
    SELECT
      dt.oid AS typid
    FROM pg_catalog.pg_type dt
    JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
    JOIN pg_catalog.pg_type bt ON bt.oid = dt.typbasetype
    JOIN pg_catalog.pg_namespace bn ON bn.oid = bt.typnamespace
    WHERE dt.typtype = 'd'
      AND bt.typname = 'jsonb'
      AND bn.nspname = 'pg_catalog'
      AND (
           dn.nspname = 'public'
        OR dn.nspname = ANY(eql_v3_internal.owned_schemas())
      )
  ),

  -- All operators where at least one operand is an EQL-owned type or a public
  -- encrypted domain. Limits the scope of the lint to the operator surface
  -- customers actually hit via SQL (`col = val`, `col @> '...'` and friends).
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
           AND (
                t.typnamespace IN (SELECT oid FROM pg_namespace WHERE nspname = ANY(eql_v3_internal.owned_schemas()))
             OR t.oid IN (SELECT typid FROM encrypted_domain_types)
           )
      )
  ),

  -- Cross-join with each operator's implementation function metadata.
  -- One row per operator; columns describe the inlinability of the impl.
  op_impl AS (
    SELECT
      eo.opname,
      eo.lhs,
      eo.rhs,
      eo.implfunc                                  AS impl_oid,
      eo.impl_signature::text                       AS impl_signature,
      lang_l.lanname                                AS lang,
      p.provolatile                                 AS volatility,
      p.proconfig                                   AS config,
      p.prosecdef                                   AS secdef,
      p.prosrc                                      AS body
    FROM eql_operators eo
    JOIN pg_proc p ON p.oid = eo.implfunc
    JOIN pg_language lang_l ON lang_l.oid = p.prolang
  ),

  -- Encrypted-domain blockers: functions in `eql_v3` whose body contains
  -- a blocker marker emitted by the codegen (any of the
  -- `encrypted_domain_unsupported_*` helper calls — `_bool` for boolean
  -- blockers, `_jsonb` for the native-jsonb-operator blockers; plus the
  -- literal `is not supported for` for older path-operator blockers) AND
  -- that take at least one encrypted domain over jsonb argument. The argument
  -- filter excludes the shared `encrypted_domain_unsupported_*(text, text)`
  -- helpers themselves, which contain the marker in their body but are not
  -- blockers (they take text arguments, not a domain).
  encrypted_domain_blockers AS (
    SELECT
      p.oid                                        AS oid,
      p.oid::regprocedure::text                    AS signature,
      lang_l.lanname                               AS lang,
      p.proisstrict                                AS isstrict
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_language lang_l ON lang_l.oid = p.prolang
    WHERE n.nspname = ANY(eql_v3_internal.owned_schemas())
      AND (p.prosrc LIKE '%encrypted_domain_unsupported%'
        OR p.prosrc LIKE '%is not supported for%')
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(p.proargtypes::oid[]) AS arg(typ)
        JOIN encrypted_domain_types edt ON edt.typid = arg.typ
      )
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
      'Operator implementation function is `LANGUAGE %s`; only `LANGUAGE sql` functions can be inlined by the planner. Bare `col %s val` queries fall back to seq scan even when a matching functional index exists.',
      lang, opname)                                                     AS message
  FROM op_impl
  WHERE lang <> 'sql'
    AND NOT EXISTS (
      SELECT 1 FROM encrypted_domain_blockers b
      WHERE b.oid = op_impl.impl_oid
    )

  UNION ALL

  SELECT
    'error',
    'inlinability_volatility',
    format('operator %s(%s, %s) -> %s', opname, lhs, rhs, impl_signature),
    format(
      'Operator implementation function is `VOLATILE`. The Postgres planner refuses to inline volatile functions into index expressions, so functional indexes never engage. Mark the function `IMMUTABLE` (or `STABLE` if it depends on session state).',
      opname)
  FROM op_impl
  WHERE volatility = 'v'
    AND NOT EXISTS (
      SELECT 1 FROM encrypted_domain_blockers b
      WHERE b.oid = op_impl.impl_oid
    )

  UNION ALL

  SELECT
    'error',
    'inlinability_set_clause',
    format('operator %s(%s, %s) -> %s', opname, lhs, rhs, impl_signature),
    format(
      'Operator implementation function has a `SET` clause (e.g. `SET search_path = ...`). Per Postgres function-inlining rules, any `SET` clause blocks inlining. Use schema-qualified identifiers in the body and remove the `SET` clause to allow the planner to inline.')
  FROM op_impl
  WHERE config IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM encrypted_domain_blockers b
      WHERE b.oid = op_impl.impl_oid
    )

  UNION ALL

  SELECT
    'error',
    'inlinability_secdef',
    format('operator %s(%s, %s) -> %s', opname, lhs, rhs, impl_signature),
    'Operator implementation function is `SECURITY DEFINER`. Such functions cannot be inlined; remove `SECURITY DEFINER` or use a non-inlinable wrapper layer.'
  FROM op_impl
  WHERE secdef
    AND NOT EXISTS (
      SELECT 1 FROM encrypted_domain_blockers b
      WHERE b.oid = op_impl.impl_oid
    )

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
      'Operator implementation function is inlinable but invokes non-inlinable function `%s` (lang=%s, volatility=%s%s). The chain blocks at depth 1: the planner inlines the outer call but cannot reduce the inner call into an index expression.',
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

  -- ┌─────────────────────────────────────────────────────────────────┐
  -- │ Encrypted-domain footguns: blockers exist to RAISE, so they     │
  -- │ have inverted inlinability requirements vs operator impls.      │
  -- │ A LANGUAGE sql blocker can be elided by the planner; a STRICT   │
  -- │ blocker returns NULL on NULL args. Both silently re-enable      │
  -- │ operators the storage variant is supposed to block.             │
  -- └─────────────────────────────────────────────────────────────────┘

  UNION ALL

  SELECT
    'error',
    'blocker_language',
    format('function %s', signature),
    format(
      'Encrypted-domain blocker is `LANGUAGE %s`; must be `LANGUAGE plpgsql` so the RAISE is opaque to the planner. A `LANGUAGE sql` body is inlinable and may be elided when the result is provably unused, silently re-enabling the operator.',
      lang)
  FROM encrypted_domain_blockers
  WHERE lang <> 'plpgsql'

  UNION ALL

  SELECT
    'error',
    'blocker_strict',
    format('function %s', signature),
    'Encrypted-domain blocker is `STRICT`. PostgreSQL skips the body and returns NULL on a NULL argument, silently bypassing the RAISE. Remove `STRICT`.'
  FROM encrypted_domain_blockers
  WHERE isstrict

  -- ┌─────────────────────────────────────────────────────────────────┐
  -- │ Domain identity: an encrypted-domain must be defined directly   │
  -- │ over jsonb. Operators resolve against the ultimate base type,   │
  -- │ so domain-over-domain inherits jsonb's operator surface and not │
  -- │ the base domain's blockers.                                     │
  -- └─────────────────────────────────────────────────────────────────┘

  UNION ALL

  SELECT
    'error',
    'domain_over_domain',
    format('domain %I.%I', dn.nspname, dt.typname),
    format(
      'Domain `%s.%s` is derived from another encrypted-domain `%s.%s` rather than jsonb. Operators resolve against the ultimate base type, so the derived domain does not inherit the base domain''s operator surface and storage blockers do not engage. Define this domain directly over jsonb.',
      dn.nspname, dt.typname, bn.nspname, bt.typname)
  FROM pg_catalog.pg_type dt
  JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
  JOIN pg_catalog.pg_type bt ON bt.oid = dt.typbasetype
  JOIN pg_catalog.pg_namespace bn ON bn.oid = bt.typnamespace
  WHERE dt.typtype = 'd'
    AND dn.nspname = ANY(eql_v3_internal.owned_schemas())
    AND bt.typtype = 'd'
    AND bt.oid IN (SELECT typid FROM encrypted_domain_types)

  -- ┌─────────────────────────────────────────────────────────────────┐
  -- │ Domain opclass: an operator class declared FOR TYPE on an       │
  -- │ encrypted-domain bypasses operator resolution at index time.    │
  -- │ Use a functional index on the extractor instead.                │
  -- └─────────────────────────────────────────────────────────────────┘

  UNION ALL

  SELECT
    'error',
    'domain_opclass',
    format('opclass %I.%I FOR TYPE %s.%s', cn.nspname, oc.opcname, tn.nspname, t.typname),
    format(
      'Operator class `%s.%s` is declared FOR TYPE `%s.%s`, which is an encrypted-domain type. Opclasses on domains bypass operator resolution. Use a functional index on the extractor (e.g. `%s.eq_term(col)`, `%s.ord_term(col)`) instead.',
      cn.nspname, oc.opcname, tn.nspname, t.typname, tn.nspname, tn.nspname)
  FROM pg_catalog.pg_opclass oc
  JOIN pg_catalog.pg_type t ON t.oid = oc.opcintype
  JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
  JOIN pg_catalog.pg_namespace cn ON cn.oid = oc.opcnamespace
  WHERE t.oid IN (SELECT typid FROM encrypted_domain_types)

  -- ┌─────────────────────────────────────────────────────────────────┐
  -- │ Schema placement: the public `eql_v3` schema must hold only the  │
  -- │ jsonb-backed encrypted-domain types. A naked composite/enum type │
  -- │ there is an internal index-term type in the wrong schema — it     │
  -- │ clutters the Supabase type picker the split exists to keep clean. │
  -- └─────────────────────────────────────────────────────────────────┘

  UNION ALL

  SELECT
    'error',
    'schema_placement',
    format('type %I.%I', n.nspname, t.typname),
    format(
      'Type `%s.%s` is a %s in the public `eql_v3` schema. Only jsonb-backed encrypted-domain types belong in `eql_v3`; internal index-term types belong in `eql_v3_internal` so they stay out of the Supabase Table Builder type picker. Move it to `eql_v3_internal`.',
      n.nspname, t.typname,
      CASE t.typtype WHEN 'c' THEN 'composite type' WHEN 'e' THEN 'enum type' ELSE 'type' END)
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'eql_v3'
    AND t.typtype IN ('c', 'e')

  ORDER BY 1, 2, 3;
$$;

COMMENT ON FUNCTION eql_v3.lints() IS
  'EQL lint: returns one row per non-inlinable operator implementation. '
  'Run `SELECT * FROM eql_v3.lints() WHERE severity = ''error''` for a '
  'CI-gateable check that all operator implementations on eql_v3 types are '
  'eligible for planner inlining.';
