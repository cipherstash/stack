import type pg from 'pg'

const LIFECYCLE_LOCK = 'cipherstash.eql.lifecycle'

/**
 * How long to keep trying for the lifecycle lock before giving up.
 *
 * Sized off what actually holds it: the whole install, which is a
 * `DROP SCHEMA … CASCADE` plus ~3,000 object creations and measures 10-30s
 * against a local container — longer on a managed Postgres. A budget of a few
 * seconds looks generous and is not; it converts ordinary queueing (two
 * installs, a CI job overlapping a developer) into a hard failure on the second
 * one. That regression is real and was caught by the live suite: with 5s, two
 * live files installing back to back failed each other.
 *
 * So: long enough that anything a waiter would sensibly wait for still
 * succeeds, and bounded so a lock nobody will release reports itself instead of
 * looking like a stalled connection.
 *
 * The budget is sized off the INSTALL, which is what actually holds the lock:
 * `DROP SCHEMA ... CASCADE` plus ~3,000 object creations, 10-30s against a
 * local container and longer on managed Postgres. The dependency capture
 * ({@link LIFECYCLE_DEPENDENCIES_SQL}) also runs under the lock but is not the
 * cost. Its recursive shape inflates PostgreSQL's estimate enough to trigger
 * JIT compilation of hundreds of expressions: measured on an idle local
 * container with EQL installed, the query itself is ~35ms with JIT disabled
 * versus ~880ms with JIT enabled. `install()` disables JIT on its dedicated
 * connection before running it.
 *
 * Five minutes is deliberate margin over that, not a measurement: a waiter
 * should never be refused for ordinary queueing, only for a holder that will
 * never release. Earlier revisions of this comment justified the number with
 * capture timings of 17-68s. Those were measured on a server concurrently
 * running the test suite and are contention, not query cost; do not reinstate
 * them as evidence.
 */
const LOCK_WAIT_MS = 300_000
const LOCK_RETRY_INTERVAL_MS = 250

/** Connections currently holding the lifecycle lock through this module. */
const lockHolders = new WeakSet<pg.ClientBase>()

export interface ReinstallIndex {
  identity: string
  definition: string
  tableIdentity: string
  valid: boolean
  ready: boolean
}

interface DependencyRow {
  dependency_kind?: unknown
  identity?: unknown
  definition?: unknown
  table_identity?: unknown
  valid?: unknown
  ready?: unknown
}

export const LIFECYCLE_DEPENDENCIES_SQL = `
/* stash_eql_lifecycle_dependencies */
WITH RECURSIVE
/*
 * A type's name spelled the way \`parseExpectedSurface\` spells it, so the
 * operator and cast identities below can be compared against the ones parsed
 * out of the bundle.
 *
 * The rule is NOT \`format_type()\`. That function omits the schema whenever the
 * type is visible on the current search_path, while the parser always emits the
 * qualification the bundle wrote (\`eql_v3.query_text_eq\`,
 * \`eql_v3_internal.ore_block_256\`). On a connection whose search_path names
 * eql_v3 — routine on a provisioned database, so an application can call
 * \`eq_term()\` unqualified — \`format_type()\` answers a bare \`query_text_eq\`,
 * every bundle-owned operator and cast misses its ownership exemption, and the
 * installer refuses on a healthy database listing EQL's own operators as
 * customer-owned. (#918)
 *
 * It is not unconditional qualification either: the bundle declares operands in
 * \`pg_catalog\` (\`text\`, \`text[]\`, \`jsonb\`, \`jsonpath\`, \`integer\`) and writes
 * them bare, so \`pg_catalog.text\` would miss in the other direction. Hence:
 * \`format_type()\` for pg_catalog — it also spells the SQL-standard multi-word
 * names (\`double precision\`) and array suffixes the parser's alias map targets
 * — and an explicit qualification for everything else.
 */
type_identity(oid, identity) AS (
  SELECT t.oid,
         CASE
           WHEN tn.nspname = 'pg_catalog'
             THEN pg_catalog.format_type(t.oid, NULL)
           -- An array of a non-catalog type: pg_type calls it \`_eql_v3_text_eq\`,
           -- the bundle would write \`public.eql_v3_text_eq[]\`.
           WHEN t.typcategory = 'A' AND et.oid IS NOT NULL
             THEN pg_catalog.format('%I.%I[]', en.nspname, et.typname)
           ELSE pg_catalog.format('%I.%I', tn.nspname, t.typname)
         END
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
  LEFT JOIN pg_catalog.pg_type et
    ON et.oid = t.typelem AND t.typcategory = 'A'
  LEFT JOIN pg_catalog.pg_namespace en ON en.oid = et.typnamespace
),
eql_roots(classid, objid, objsubid) AS (
  SELECT 'pg_catalog.pg_namespace'::regclass, n.oid, 0
  FROM pg_catalog.pg_namespace n
  WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
  UNION ALL
  SELECT 'pg_catalog.pg_proc'::regclass, p.oid, 0
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
  UNION ALL
  SELECT 'pg_catalog.pg_type'::regclass, t.oid, 0
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
  UNION ALL
  SELECT 'pg_catalog.pg_operator'::regclass, o.oid, 0
  FROM pg_catalog.pg_operator o
  JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
  WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
  UNION ALL
  SELECT 'pg_catalog.pg_opclass'::regclass, o.oid, 0
  FROM pg_catalog.pg_opclass o
  JOIN pg_catalog.pg_namespace n ON n.oid = o.opcnamespace
  WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
  UNION ALL
  SELECT 'pg_catalog.pg_opfamily'::regclass, o.oid, 0
  FROM pg_catalog.pg_opfamily o
  JOIN pg_catalog.pg_namespace n ON n.oid = o.opfnamespace
  WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
),
/*
 * Everything reachable from the bundle, transitively. The lateral is one
 * recursive self-reference carrying two kinds of edge, because PostgreSQL
 * permits only one.
 *
 * The first is the ordinary one: whatever depends on the object we are
 * standing on.
 *
 * The second exists because a view's dependency on an EQL function is recorded
 * against its rewrite RULE, not against the view, and nothing in pg_depend
 * leads from the rule back out to the view — the rule's own edge to it points
 * the wrong way. Walking edge one alone therefore stops at
 * \`"_RETURN" on public.v1\` and never learns that v1 is a view, that v2 selects
 * from v1, or that v3 selects from v2. The refusal was still correct (a rule is
 * not a rebuildable index, so the install refused) but it named a rule where
 * three views were at stake, and under-reported the blast radius to whoever had
 * to decide what to do about it.
 *
 * Restricted to \`relkind IN ('v', 'm')\` deliberately. A view cannot outlive its
 * _RETURN rule, so the view really is destroyed and really is the better name.
 * A rule on an ordinary TABLE is different: dropping the rule leaves the table
 * standing, so hopping there would name a table that survives, and the rule
 * stays the honest answer.
 */
dependency_edges(refclassid, refobjid, refobjsubid, classid, objid, objsubid) AS (
  SELECT d.refclassid, d.refobjid, d.refobjsubid, d.classid, d.objid, d.objsubid
  FROM pg_catalog.pg_depend d
  UNION ALL
  SELECT 'pg_catalog.pg_rewrite'::regclass, rewrite_rule.oid, 0,
         'pg_catalog.pg_class'::regclass, view_class.oid, 0
  FROM pg_catalog.pg_rewrite rewrite_rule
  JOIN pg_catalog.pg_class view_class ON view_class.oid = rewrite_rule.ev_class
  WHERE view_class.relkind IN ('v', 'm')
),
dependants(classid, objid, objsubid) AS (
  SELECT classid, objid, objsubid FROM eql_roots
  UNION
  SELECT e.classid, e.objid, e.objsubid
  FROM dependency_edges e
  JOIN dependants parent
    ON e.refclassid = parent.classid
   AND e.refobjid = parent.objid
   AND (parent.objsubid = 0 OR e.refobjsubid = parent.objsubid)
),
external_dependants AS (
  SELECT d.classid, d.objid, d.objsubid
  FROM dependants d
  WHERE NOT EXISTS (
    SELECT 1 FROM eql_roots r
    WHERE r.classid = d.classid
      AND r.objid = d.objid
      AND r.objsubid = d.objsubid
  )
  -- Objects whose own namespace is disposable are bundle contents, even when
  -- they were reached indirectly through an operator family or row type.
  AND COALESCE(
    (pg_catalog.pg_identify_object(d.classid, d.objid, d.objsubid)).schema,
    ''
  ) NOT IN ('eql_v3', 'eql_v3_internal')
  -- A relation drags its composite row type and that type's array type along.
  -- Both name the same casualty the relation already names (\`public.v1\`,
  -- \`public.v1[]\`), so report the relation once and drop the two types.
  AND NOT (
    d.classid = 'pg_catalog.pg_type'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_type shadow
      LEFT JOIN pg_catalog.pg_type element ON element.oid = shadow.typelem
      WHERE shadow.oid = d.objid
        AND COALESCE(element.typrelid, shadow.typrelid) <> 0
    )
  )
  -- The view this rule belongs to is now in the walk and is the better name for
  -- the same casualty, so report the view and drop the rule rather than both.
  AND NOT (
    d.classid = 'pg_catalog.pg_rewrite'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_rewrite rewrite_rule
      JOIN pg_catalog.pg_class view_class ON view_class.oid = rewrite_rule.ev_class
      WHERE rewrite_rule.oid = d.objid
        AND view_class.relkind IN ('v', 'm')
    )
  )
  AND NOT (
    d.classid = 'pg_catalog.pg_constraint'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_type typ ON typ.oid = con.contypid
      JOIN pg_catalog.pg_namespace n ON n.oid = typ.typnamespace
      WHERE con.oid = d.objid
        AND (
          n.nspname IN ('eql_v3', 'eql_v3_internal')
          OR (
            con.conname = 'eql_ore_unavailable'
            AND n.nspname = 'public'
            AND typ.typname LIKE 'eql\\_v3\\_%' ESCAPE '\\'
          )
        )
    )
  )
  AND NOT (
    d.classid = 'pg_catalog.pg_proc'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc proc
      JOIN pg_catalog.pg_namespace n ON n.oid = proc.pronamespace
      WHERE proc.oid = d.objid
        AND n.nspname IN ('eql_v3', 'eql_v3_internal')
    )
  )
  AND NOT (
    d.classid = 'pg_catalog.pg_class'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class class
      JOIN pg_catalog.pg_namespace n ON n.oid = class.relnamespace
      WHERE class.oid = d.objid
        AND n.nspname IN ('eql_v3', 'eql_v3_internal')
    )
  )
  -- Only exact operator identities parsed from the pinned bundle are owned by
  -- EQL. A customer may legally give an EQL function a different operator
  -- name, so implementation namespace alone is not an ownership marker.
  AND NOT (
    d.classid = 'pg_catalog.pg_operator'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_operator operator
      -- Prefix operators carry oprleft = 0, which matches no pg_type row; the
      -- parser writes that operand as \`none\`.
      LEFT JOIN type_identity left_type ON left_type.oid = operator.oprleft
      LEFT JOIN type_identity right_type ON right_type.oid = operator.oprright
      WHERE operator.oid = d.objid
        AND pg_catalog.lower(operator.oprname) || ' (' ||
            COALESCE(left_type.identity, 'none') || ', ' ||
            COALESCE(right_type.identity, 'none') || ')'
            = ANY($1::text[])
        -- Compared raw, NOT through lower(). Postgres operator names are drawn
        -- from +-*/<>=~!@#%^&|? and cannot contain a letter, so lower() is a
        -- no-op on the value -- but it is not a no-op on the plan: it makes
        -- pg_operator_oprname_l_r_n_index (oprname, oprleft, oprright,
        -- oprnamespace) unusable and turns this into a sequential scan. The
        -- planner evaluates this count as a filter over the whole of
        -- pg_operator before operator.oid = d.objid narrows anything, so
        -- with lower() the guard is a self-join of pg_operator against itself:
        -- ~3,900 rows squared, ~15M comparisons and ~9GB of buffer traffic on
        -- a database with EQL installed, which is most of this query's cost.
        -- Do not reintroduce it.
        AND (
          SELECT pg_catalog.count(*)
          FROM pg_catalog.pg_operator candidate
          WHERE candidate.oprname = operator.oprname
            AND candidate.oprleft = operator.oprleft
            AND candidate.oprright = operator.oprright
        ) = 1
    )
  )
  -- Likewise, these public-data-domain <-> query-domain casts are declarations
  -- in the bundle, not application objects.
  AND NOT (
    d.classid = 'pg_catalog.pg_cast'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_cast cast_row
      JOIN type_identity source_type ON source_type.oid = cast_row.castsource
      JOIN type_identity target_type ON target_type.oid = cast_row.casttarget
      WHERE cast_row.oid = d.objid
        AND source_type.identity || ' AS ' || target_type.identity
            = ANY($2::text[])
    )
  )
  -- pg_amop/pg_amproc have no namespace of their own; their owning family does.
  AND NOT (
    d.classid IN (
      'pg_catalog.pg_amop'::regclass,
      'pg_catalog.pg_amproc'::regclass
    )
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_opfamily family
      JOIN pg_catalog.pg_namespace n ON n.oid = family.opfnamespace
      WHERE family.oid = CASE
        WHEN d.classid = 'pg_catalog.pg_amop'::regclass
          THEN (SELECT amopfamily FROM pg_catalog.pg_amop WHERE oid = d.objid)
        ELSE (SELECT amprocfamily FROM pg_catalog.pg_amproc WHERE oid = d.objid)
      END
      AND n.nspname IN ('eql_v3', 'eql_v3_internal')
    )
  )
)
/*
 * \`i\` is an ordinary index; \`I\` is a PARTITIONED index — the parent template on
 * a partitioned table. Both are rebuildable, but only together: the parent's
 * \`pg_get_indexdef\` says \`ON ONLY\`, its per-partition children come back as
 * separate \`i\` rows, and the parent stays \`indisvalid = false\` until every one
 * of them is re-ATTACHed. \`parent_identity\` (from pg_inherits, which relates an
 * attached child index to its parent) is what carries that edge across the
 * DROP; see {@link rebuildIndexes}.
 */
SELECT DISTINCT
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL THEN 'index'
    ELSE 'unsafe'
  END AS dependency_kind,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL
      THEN pg_catalog.format('%I.%I', index_namespace.nspname, index_class.relname)
    ELSE (pg_catalog.pg_identify_object(e.classid, e.objid, e.objsubid)).identity
  END AS identity,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL THEN pg_catalog.pg_get_indexdef(e.objid)
  END AS definition,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL
      THEN pg_catalog.format('%I.%I', table_namespace.nspname, table_class.relname)
  END AS table_identity,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL THEN index_meta.indisvalid
  END AS valid,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL THEN index_meta.indisready
  END AS ready
FROM external_dependants e
LEFT JOIN pg_catalog.pg_class index_class
  ON e.classid = 'pg_catalog.pg_class'::regclass AND index_class.oid = e.objid
LEFT JOIN pg_catalog.pg_inherits index_partition
  ON index_partition.inhrelid = index_class.oid
LEFT JOIN pg_catalog.pg_namespace index_namespace ON index_namespace.oid = index_class.relnamespace
LEFT JOIN pg_catalog.pg_index index_meta ON index_meta.indexrelid = index_class.oid
LEFT JOIN pg_catalog.pg_class table_class ON table_class.oid = index_meta.indrelid
LEFT JOIN pg_catalog.pg_namespace table_namespace ON table_namespace.oid = table_class.relnamespace
ORDER BY dependency_kind, identity
`

const VERIFY_REBUILT_INDEXES_SQL = `
/* stash_eql_verify_rebuilt_indexes */
SELECT pg_catalog.format('%I.%I', n.nspname, c.relname) AS identity,
       i.indisvalid AS valid,
       i.indisready AS ready,
       pg_catalog.pg_get_indexdef(i.indexrelid) AS definition
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE pg_catalog.format('%I.%I', n.nspname, c.relname) = ANY($1::text[])
`

/**
 * Take the installer's advisory lock, or say why not.
 *
 * `pg_advisory_lock` waits forever. A concurrent `stash eql install`, or a
 * session that died holding the lock, then makes the command hang with no
 * output and no timeout — indistinguishable from a network stall, and the one
 * failure a user cannot diagnose. Polling `pg_try_advisory_lock` against a
 * bounded budget keeps the ordinary case working — a queued install still wins
 * the lock and runs — while turning the pathological one into a sentence. See
 * {@link LOCK_WAIT_MS} for why the budget is a minute and not the handful of
 * seconds it first was. (#959)
 */
export async function acquireLifecycleLock(
  client: pg.ClientBase,
  // Optional so `acquireLifecycleLock(client)` keeps meaning what it did. The
  // budget is a policy, not a constant of nature, and the live suite drives it
  // short to assert the refusal without waiting out the production default.
  waitMs: number = LOCK_WAIT_MS,
) {
  const deadline = Date.now() + waitMs
  for (;;) {
    const result = await client.query<{ acquired: boolean }>(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired',
      [LIFECYCLE_LOCK],
    )
    if (result.rows[0]?.acquired === true) {
      lockHolders.add(client)
      return
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `Another EQL lifecycle operation is in progress on this database — it has held the installer's advisory lock for more than ${Math.round(waitMs / 1000)} seconds. Nothing was changed. Wait for the other \`stash eql install\`/\`eql upgrade\` to finish and re-run. If no other command is running, an earlier one may have died holding the lock: find its session in \`pg_stat_activity\` and close it, then retry.`,
      )
    }
    // Deliberately NOT unref'd: the retry is the only pending work between
    // polls, and letting Node drop it would end the process mid-install.
    await new Promise((resolve) => setTimeout(resolve, LOCK_RETRY_INTERVAL_MS))
  }
}

/**
 * Release the lock if this connection took it. The caller unlocks
 * unconditionally in a `finally`, which includes the path where the acquire
 * above refused — and `pg_advisory_unlock` on a lock a session never held
 * returns false and raises a WARNING, i.e. noise on the one path that already
 * has a clear message.
 */
export async function releaseLifecycleLock(client: pg.ClientBase) {
  if (!lockHolders.has(client)) return
  lockHolders.delete(client)
  await client.query('SELECT pg_advisory_unlock(hashtext($1))', [
    LIFECYCLE_LOCK,
  ])
}

export async function inspectReinstallDependencies(
  client: pg.ClientBase,
  bundleOperators: string[],
  bundleCasts: string[],
): Promise<ReinstallIndex[]> {
  const result = await client.query(LIFECYCLE_DEPENDENCIES_SQL, [
    bundleOperators,
    bundleCasts,
  ])
  const unsafe: string[] = []
  const indexes: ReinstallIndex[] = []
  for (const row of result.rows as DependencyRow[]) {
    if (row.dependency_kind !== 'index') {
      unsafe.push(String(row.identity ?? 'unknown database object'))
      continue
    }
    if (
      typeof row.identity !== 'string' ||
      typeof row.definition !== 'string' ||
      typeof row.table_identity !== 'string' ||
      typeof row.valid !== 'boolean' ||
      typeof row.ready !== 'boolean'
    ) {
      unsafe.push(
        String(row.identity ?? 'index with incomplete catalog metadata'),
      )
      continue
    }
    indexes.push({
      identity: row.identity,
      definition: row.definition,
      tableIdentity: row.table_identity,
      valid: row.valid,
      ready: row.ready,
    })
  }
  if (unsafe.length > 0) {
    throw new Error(
      `EQL reinstall refused before making changes because customer-owned database objects depend on disposable EQL machinery and cannot be reconstructed safely:\n${unsafe.map((identity) => `  - ${identity}`).join('\n')}`,
    )
  }
  return indexes
}

/**
 * Recreate captured ordinary indexes and verify their exact catalog shape.
 *
 * `pg_get_indexdef` is itself search_path-sensitive: on a connection whose
 * search_path names `eql_v3` the captured definition reads `eq_term(encrypted)`
 * rather than `eql_v3.eq_term(encrypted)`. That is safe here and deliberately
 * not "fixed" — the same session rebuilds it, and Postgres qualifies a name
 * exactly when leaving it bare would resolve to something else, so the
 * rebuilt expression binds to the same function the original did.
 *
 */
export async function rebuildIndexes(
  client: pg.ClientBase,
  indexes: ReinstallIndex[],
) {
  for (const index of indexes) {
    try {
      await client.query(index.definition)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(
        `EQL reinstall could not rebuild search index ${index.identity}: ${detail}\nThe transaction will restore the previous EQL installation and index. Captured index SQL:\n${index.definition}`,
        { cause: error },
      )
    }
  }
  for (const tableIdentity of new Set(
    indexes.map((index) => index.tableIdentity),
  )) {
    await client.query(`ANALYZE ${tableIdentity}`)
  }
  if (indexes.length === 0) return
  const result = await client.query(VERIFY_REBUILT_INDEXES_SQL, [
    indexes.map((index) => index.identity),
  ])
  const healthy = new Set(
    result.rows
      .filter((row) => {
        const expected = indexes.find(
          (index) => index.identity === row.identity,
        )
        if (expected === undefined) return false
        // The definition must match EXACTLY: it is the only evidence that the
        // index which came back is the index that went away.
        //
        // Validity is compared against what was CAPTURED rather than against
        // `true`, because an index can already be invalid going in and the
        // reinstall does not promise to repair one it did not break — a
        // partitioned parent created `ON ONLY` while its per-partition indexes
        // are still being built, or an interrupted `CREATE INDEX CONCURRENTLY`.
        // Demanding `true` there fails the whole install and the rollback says
        // nothing about why. A VALID index coming back invalid is still caught;
        // that is the regression this check exists for.
        return (
          expected.definition === row.definition &&
          (row.valid === true || expected.valid === false) &&
          (row.ready === true || expected.ready === false)
        )
      })
      .map((row) => String(row.identity)),
  )
  const unhealthy = indexes.filter((index) => !healthy.has(index.identity))
  if (unhealthy.length > 0) {
    throw new Error(
      `EQL reinstall produced missing, invalid, or changed search indexes; the transaction will restore the previous installation:\n${unhealthy.map((index) => `  - ${index.identity}\n    ${index.definition}`).join('\n')}`,
    )
  }
}
