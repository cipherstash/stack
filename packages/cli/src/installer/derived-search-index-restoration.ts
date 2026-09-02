import type pg from 'pg'

import { createPgClient, TlsVerificationError } from '@/db/client.js'

const LIFECYCLE_LOCK = 'cipherstash.eql.lifecycle'

/**
 * How long to keep trying for the lifecycle lock before giving up.
 *
 * The budget is sized off the INSTALL, which is what actually holds the lock:
 * `DROP SCHEMA ... CASCADE` plus ~3,000 object creations, 10-30s against a
 * local container and longer on managed Postgres. The dependency capture
 * ({@link LIFECYCLE_DEPENDENCIES_SQL}) also runs under the lock but is not the
 * cost. Its recursive shape inflates PostgreSQL's estimate enough to trigger
 * JIT compilation of hundreds of expressions: measured on an idle local
 * container with EQL installed, the query itself is ~35ms with JIT disabled
 * versus ~880ms with JIT enabled. `install()` disables JIT for its transaction.
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

export class EqlReinstallRefusalError extends Error {}

export class EqlReinstallConnectionError extends Error {}

export class EqlLifecycleLockTimeoutError extends Error {}

export class DerivedSearchIndexReconstructionError extends Error {}

export class DerivedSearchIndexVerificationError extends Error {}

export interface RestorationSummary {
  restoredIndexes: number
  analyzedTables: number
}

interface RestoreAroundEqlReplacementOptions {
  databaseUrl: string
  bundledSql: string
}

export interface ReinstallIndex {
  identity: string
  definition: string
  tableIdentity: string
  valid: boolean
  ready: boolean
  clustered: boolean
  clusterSql: string | null
  replicaIdentity: boolean
  replicaIdentitySql: string | null
  comment: string | null
  commentSql: string | null
  owner: string
  statisticsTargets: Array<number | null>
  statisticsSql: string[]
}

interface DependencyRow {
  dependency_kind?: unknown
  identity?: unknown
  definition?: unknown
  table_identity?: unknown
  valid?: unknown
  ready?: unknown
  clustered?: unknown
  cluster_sql?: unknown
  replica_identity?: unknown
  replica_identity_sql?: unknown
  comment?: unknown
  comment_sql?: unknown
  owner?: unknown
  statistics_targets?: unknown
  statistics_sql?: unknown
}

const LIFECYCLE_DEPENDENCIES_SQL = `
/* stash_eql_lifecycle_dependencies */
WITH RECURSIVE
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
  -- EQL installs its operators in public and implements them with functions in
  -- a disposable EQL schema. Classify the installed catalog, not the incoming
  -- bundle: an upgrade may legitimately remove an old operator.
  AND NOT (
    d.classid = 'pg_catalog.pg_operator'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_operator operator
      JOIN pg_catalog.pg_namespace operator_namespace
        ON operator_namespace.oid = operator.oprnamespace
      JOIN pg_catalog.pg_proc implementation
        ON implementation.oid = operator.oprcode
      JOIN pg_catalog.pg_namespace implementation_namespace
        ON implementation_namespace.oid = implementation.pronamespace
      WHERE operator.oid = d.objid
        AND operator_namespace.nspname = 'public'
        AND implementation_namespace.nspname IN ('eql_v3', 'eql_v3_internal')
    )
  )
  -- Likewise, EQL's casts are implemented by functions in the disposable EQL
  -- schemas. Classify the installed catalog rather than the incoming bundle:
  -- an upgrade may legitimately remove an old cast.
  AND NOT (
    d.classid = 'pg_catalog.pg_cast'::regclass
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_cast cast_row
      JOIN pg_catalog.pg_proc implementation
        ON implementation.oid = cast_row.castfunc
      JOIN pg_catalog.pg_namespace implementation_namespace
        ON implementation_namespace.oid = implementation.pronamespace
      WHERE cast_row.oid = d.objid
        AND implementation_namespace.nspname IN ('eql_v3', 'eql_v3_internal')
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
 * Only standalone ordinary indexes are reconstructed. Partitioned index parents
 * (\`I\`) and attached child indexes are classified as unsafe because recreating
 * their attachment graph requires metadata beyond \`pg_get_indexdef\`.
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
  END AS ready,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL THEN index_meta.indisclustered
  END AS clustered,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL THEN index_meta.indisreplident
  END AS replica_identity,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL
      THEN pg_catalog.obj_description(index_class.oid, 'pg_class')
  END AS comment,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL
     AND index_meta.indisclustered
      THEN pg_catalog.format(
        'ALTER TABLE %I.%I CLUSTER ON %I',
        table_namespace.nspname,
        table_class.relname,
        index_class.relname
      )
  END AS cluster_sql,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL
     AND index_meta.indisreplident
      THEN pg_catalog.format(
        'ALTER TABLE %I.%I REPLICA IDENTITY USING INDEX %I',
        table_namespace.nspname,
        table_class.relname,
        index_class.relname
      )
  END AS replica_identity_sql,
  CASE
    WHEN e.classid = 'pg_catalog.pg_class'::regclass
     AND index_class.relkind = 'i'
     AND index_partition.inhrelid IS NULL
     AND pg_catalog.obj_description(index_class.oid, 'pg_class') IS NOT NULL
      THEN pg_catalog.format(
        'COMMENT ON INDEX %I.%I IS %L',
        index_namespace.nspname,
        index_class.relname,
        pg_catalog.obj_description(index_class.oid, 'pg_class')
      )
  END AS comment_sql
  , pg_catalog.pg_get_userbyid(index_class.relowner) AS owner
  , CASE
      WHEN e.classid = 'pg_catalog.pg_class'::regclass
       AND index_class.relkind = 'i'
       AND index_partition.inhrelid IS NULL
        THEN ARRAY(
          SELECT attribute.attstattarget
          FROM pg_catalog.pg_attribute attribute
          WHERE attribute.attrelid = index_class.oid
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
          ORDER BY attribute.attnum
        )
    END AS statistics_targets
  , CASE
      WHEN e.classid = 'pg_catalog.pg_class'::regclass
       AND index_class.relkind = 'i'
       AND index_partition.inhrelid IS NULL
        THEN ARRAY(
          SELECT pg_catalog.format(
            'ALTER INDEX %I.%I ALTER COLUMN %s SET STATISTICS %s',
            index_namespace.nspname,
            index_class.relname,
            attribute.attnum,
            attribute.attstattarget
          )
          FROM pg_catalog.pg_attribute attribute
          WHERE attribute.attrelid = index_class.oid
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
            AND attribute.attstattarget >= 0
          ORDER BY attribute.attnum
        )
    END AS statistics_sql
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
       i.indisclustered AS clustered,
       i.indisreplident AS replica_identity,
       pg_catalog.obj_description(c.oid, 'pg_class') AS comment,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner,
       ARRAY(
         SELECT attribute.attstattarget
         FROM pg_catalog.pg_attribute attribute
         WHERE attribute.attrelid = c.oid
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
         ORDER BY attribute.attnum
       ) AS statistics_targets,
       pg_catalog.pg_get_indexdef(i.indexrelid) AS definition
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE pg_catalog.format('%I.%I', n.nspname, c.relname) = ANY($1::text[])
`

/**
 * Take the installer's advisory lock, or say why not.
 *
 * `pg_advisory_xact_lock` waits forever. A concurrent `stash eql install`, or a
 * session that died holding the lock, then makes the command hang with no
 * output and no timeout — indistinguishable from a network stall, and the one
 * failure a user cannot diagnose. Polling `pg_try_advisory_xact_lock` against a
 * bounded budget keeps the ordinary case working — a queued install still wins
 * the lock and runs — while turning the pathological one into a sentence. See
 * {@link LOCK_WAIT_MS} for why the five-minute budget is not the handful of
 * seconds it first was. (#959)
 */
async function acquireLifecycleLock(
  client: pg.ClientBase,
  // Optional so `acquireLifecycleLock(client)` keeps meaning what it did. The
  // budget is a policy, not a constant of nature, and the live suite drives it
  // short to assert the refusal without waiting out the production default.
  waitMs: number = LOCK_WAIT_MS,
) {
  const deadline = Date.now() + waitMs
  for (;;) {
    const result = await client.query<{ acquired: boolean }>(
      'SELECT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtext($1)) AS acquired',
      [LIFECYCLE_LOCK],
    )
    if (result.rows[0]?.acquired === true) {
      return
    }
    if (Date.now() >= deadline) {
      throw new EqlLifecycleLockTimeoutError(
        `Another EQL lifecycle operation is in progress on this database — it has held the installer's advisory lock for more than ${Math.round(waitMs / 1000)} seconds. Nothing was changed. Wait for the other \`stash eql install\`/\`eql upgrade\` to finish and re-run. If no other command is running, an earlier one may have died holding the lock: find its session in \`pg_stat_activity\` and close it, then retry.`,
      )
    }
    // Deliberately NOT unref'd: the retry is the only pending work between
    // polls, and letting Node drop it would end the process mid-install.
    await new Promise((resolve) => setTimeout(resolve, LOCK_RETRY_INTERVAL_MS))
  }
}

async function inspectReinstallDependencies(
  client: pg.ClientBase,
): Promise<ReinstallIndex[]> {
  const result = await client.query(LIFECYCLE_DEPENDENCIES_SQL)
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
      typeof row.ready !== 'boolean' ||
      typeof row.clustered !== 'boolean' ||
      typeof row.replica_identity !== 'boolean' ||
      (row.cluster_sql !== null && typeof row.cluster_sql !== 'string') ||
      (row.clustered && typeof row.cluster_sql !== 'string') ||
      (row.replica_identity_sql !== null &&
        typeof row.replica_identity_sql !== 'string') ||
      (row.replica_identity && typeof row.replica_identity_sql !== 'string') ||
      (row.comment !== null && typeof row.comment !== 'string') ||
      (row.comment_sql !== null && typeof row.comment_sql !== 'string') ||
      (typeof row.comment === 'string' &&
        typeof row.comment_sql !== 'string') ||
      typeof row.owner !== 'string' ||
      !Array.isArray(row.statistics_targets) ||
      !row.statistics_targets.every(
        (target) => target === null || typeof target === 'number',
      ) ||
      !Array.isArray(row.statistics_sql) ||
      !row.statistics_sql.every((sql) => typeof sql === 'string')
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
      clustered: row.clustered,
      clusterSql: row.cluster_sql,
      replicaIdentity: row.replica_identity,
      replicaIdentitySql: row.replica_identity_sql,
      comment: row.comment,
      commentSql: row.comment_sql,
      owner: row.owner,
      statisticsTargets: row.statistics_targets,
      statisticsSql: row.statistics_sql,
    })
  }
  if (unsafe.length > 0) {
    throw new EqlReinstallRefusalError(
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
async function rebuildIndexes(
  client: pg.ClientBase,
  indexes: ReinstallIndex[],
) {
  for (const index of indexes) {
    try {
      await client.query(index.definition)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new DerivedSearchIndexReconstructionError(
        `EQL reinstall could not rebuild search index ${index.identity}: ${detail}\nThe transaction will restore the previous EQL installation and index. Captured index SQL:\n${index.definition}`,
        { cause: error },
      )
    }
  }
  for (const index of indexes) {
    if (index.clusterSql !== null) await client.query(index.clusterSql)
    if (index.replicaIdentitySql !== null)
      await client.query(index.replicaIdentitySql)
    if (index.commentSql !== null) await client.query(index.commentSql)
    for (const statisticsSql of index.statisticsSql) {
      await client.query(statisticsSql)
    }
  }
  const tableIdentities = new Set(indexes.map((index) => index.tableIdentity))
  for (const tableIdentity of tableIdentities) {
    await client.query(`ANALYZE ${tableIdentity}`)
  }
  if (indexes.length === 0) {
    return { restoredIndexes: 0, analyzedTables: 0 }
  }
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
          (row.ready === true || expected.ready === false) &&
          row.clustered === expected.clustered &&
          row.replica_identity === expected.replicaIdentity &&
          (row.comment ?? null) === expected.comment &&
          row.owner === expected.owner &&
          Array.isArray(row.statistics_targets) &&
          row.statistics_targets.length === expected.statisticsTargets.length &&
          row.statistics_targets.every(
            (target: unknown, position: number) =>
              target === expected.statisticsTargets[position],
          )
        )
      })
      .map((row) => String(row.identity)),
  )
  const unhealthy = indexes.filter((index) => !healthy.has(index.identity))
  if (unhealthy.length > 0) {
    throw new DerivedSearchIndexVerificationError(
      `EQL reinstall produced missing, invalid, or changed search indexes; the transaction will restore the previous installation:\n${unhealthy.map((index) => `  - ${index.identity}\n    ${index.definition}`).join('\n')}`,
    )
  }
  return {
    restoredIndexes: indexes.length,
    analyzedTables: tableIdentities.size,
  }
}

/**
 * Replace EQL machinery while preserving every reconstructable derived search
 * index in one transaction. Catalog discovery, reconstruction details, and
 * verification remain private so callers cannot execute the protocol out of
 * order or retain stale captured state.
 */
export async function restoreDerivedSearchIndexesAroundEqlReplacement({
  databaseUrl,
  bundledSql,
}: RestoreAroundEqlReplacementOptions): Promise<RestorationSummary> {
  const client = createPgClient(databaseUrl)
  try {
    await client.connect()
  } catch (error) {
    await client.end().catch(() => {})
    if (error instanceof TlsVerificationError) throw error
    const detail = error instanceof Error ? error.message : String(error)
    throw new EqlReinstallConnectionError(
      `Failed to connect to database: ${detail}`,
      {
        cause: error,
      },
    )
  }

  try {
    await client.query('BEGIN')
    try {
      await acquireLifecycleLock(client)
      await client.query('SET LOCAL jit = off')
      const indexes = await inspectReinstallDependencies(client)
      await client.query(bundledSql)
      const summary = await rebuildIndexes(client, indexes)
      await client.query('COMMIT')
      return summary
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {})
      throw error
    }
  } finally {
    await client.end()
  }
}

/** @internal Direct catalog probes retained only for live PostgreSQL evidence. */
export const derivedSearchIndexRestorationTestSeam = {
  acquireLifecycleLock,
  lifecycleDependenciesSql: LIFECYCLE_DEPENDENCIES_SQL,
}
