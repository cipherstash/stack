/**
 * Live-Postgres coverage for safe EQL schema replacement.
 *
 * The catalog dependency graph and pg_get_indexdef() are the public seam: a
 * mock cannot prove PostgreSQL records an expression-index or policy dependency
 * in the shape our classifier expects. Two of the checks below go further and
 * are unreproducible anywhere else: `format_type()`'s search_path sensitivity
 * and `ALTER INDEX … ATTACH PARTITION`'s effect on `indisvalid` are behaviours
 * of the server, not properties of our SQL text.
 */

import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { derivedSearchIndexRestorationTestSeam } from '../derived-search-index-restoration.js'
import { EQLInstaller, loadBundledEqlSql } from '../index.js'
import { parseExpectedSurface } from '../verify.js'

const { acquireLifecycleLock, lifecycleDependenciesSql } =
  derivedSearchIndexRestorationTestSeam

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

async function queryOn<T = unknown>(
  url: string,
  sql: string,
  params: unknown[] = [],
): Promise<T[]> {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: url })
  await client.connect()
  try {
    return (await client.query(sql, params)).rows as T[]
  } finally {
    await client.end().catch(() => undefined)
  }
}

async function query<T = unknown>(sql: string): Promise<T[]> {
  return queryOn<T>(DATABASE_URL ?? '', sql)
}

/**
 * The same database, reached on a connection whose `search_path` names the EQL
 * schemas. Provisioned databases routinely carry this (`ALTER ROLE … SET
 * search_path`) so applications can call `eq_term()` unqualified — and it is
 * the one condition under which `format_type()` stops schema-qualifying EQL's
 * own types.
 */
function withEqlSearchPath(url: string): string {
  const parsed = new URL(url)
  parsed.searchParams.set(
    'options',
    '-c search_path=public,eql_v3,eql_v3_internal',
  )
  return parsed.toString()
}

/**
 * Every index in the test schema, with the two things a partitioned rebuild
 * can silently lose: its validity, and which partitioned index it is attached
 * to.
 */
const INDEX_STATE_SQL = `
  SELECT pg_catalog.format('%I.%I', n.nspname, c.relname) AS identity,
         c.relkind::text AS relkind,
         i.indisvalid AS valid,
         i.indisready AS ready,
         pg_catalog.pg_get_indexdef(i.indexrelid) AS definition,
         (
           SELECT pg_catalog.format('%I.%I', pn.nspname, pc.relname)
           FROM pg_catalog.pg_inherits inh
           JOIN pg_catalog.pg_class pc ON pc.oid = inh.inhparent
           JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
           WHERE inh.inhrelid = c.oid
         ) AS attached_to
  FROM pg_catalog.pg_index i
  JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'stash_reinstall_test'
  ORDER BY identity
`

describeLive('EQLInstaller safe reinstall — live Postgres', () => {
  beforeEach(async () => {
    await query('DROP EVENT TRIGGER IF EXISTS stash_reinstall_pause_drop')
    await query('DROP SCHEMA IF EXISTS stash_reinstall_test CASCADE')
    await new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install()
    await query(`
      CREATE SCHEMA IF NOT EXISTS stash_reinstall_test;
      DROP TABLE IF EXISTS stash_reinstall_test.records CASCADE;
      CREATE TABLE stash_reinstall_test.records (
        id integer PRIMARY KEY,
        encrypted public.eql_v3_text_eq NOT NULL
      );
      INSERT INTO stash_reinstall_test.records VALUES
        (1, '{"v":3,"i":{},"c":"ciphertext","hm":"term"}'::jsonb);
    `)
  }, 180_000)

  afterAll(async () => {
    await query('DROP SCHEMA IF EXISTS stash_reinstall_test CASCADE').catch(
      () => undefined,
    )
  })

  it('preserves data and rebuilds a functional index', async () => {
    await query(`
      CREATE INDEX records_encrypted_idx
        ON stash_reinstall_test.records (eql_v3.eq_term(encrypted));
      CREATE UNIQUE INDEX "Records encrypted complex"
        ON stash_reinstall_test.records USING btree (eql_v3.eq_term(encrypted))
        INCLUDE (id) WITH (fillfactor = 80) WHERE id > 0;
    `)
    const identityBefore = await query<{
      table_oid: string
      column_number: number
      column_type_oid: string
      value: unknown
    }>(`
      SELECT c.oid::text AS table_oid,
             a.attnum AS column_number,
             a.atttypid::text AS column_type_oid,
             r.encrypted::jsonb AS value
      FROM stash_reinstall_test.records r
      JOIN pg_catalog.pg_class c
        ON c.oid = 'stash_reinstall_test.records'::regclass
      JOIN pg_catalog.pg_attribute a
        ON a.attrelid = c.oid AND a.attname = 'encrypted'
      WHERE r.id = 1
    `)
    const definitionsBefore = await query<{
      identity: string
      definition: string
    }>(`
      SELECT c.relname AS identity, pg_catalog.pg_get_indexdef(c.oid) AS definition
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'stash_reinstall_test'
        AND c.relname IN ('records_encrypted_idx', 'Records encrypted complex')
      ORDER BY c.relname
    `)
    await new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install()

    const rows = await query<{
      value: unknown
      index_valid: boolean
      index_ready: boolean
    }>(`
      SELECT r.encrypted::jsonb AS value,
             i.indisvalid AS index_valid,
             i.indisready AS index_ready
      FROM stash_reinstall_test.records r
      CROSS JOIN pg_catalog.pg_index i
      WHERE r.id = 1
        AND i.indexrelid = 'stash_reinstall_test.records_encrypted_idx'::regclass
    `)
    expect(rows).toEqual([
      {
        value: { v: 3, i: {}, c: 'ciphertext', hm: 'term' },
        index_valid: true,
        index_ready: true,
      },
    ])
    expect(
      await query<{
        table_oid: string
        column_number: number
        column_type_oid: string
        value: unknown
      }>(`
        SELECT c.oid::text AS table_oid,
               a.attnum AS column_number,
               a.atttypid::text AS column_type_oid,
               r.encrypted::jsonb AS value
        FROM stash_reinstall_test.records r
        JOIN pg_catalog.pg_class c
          ON c.oid = 'stash_reinstall_test.records'::regclass
        JOIN pg_catalog.pg_attribute a
          ON a.attrelid = c.oid AND a.attname = 'encrypted'
        WHERE r.id = 1
      `),
    ).toEqual(identityBefore)
    expect(
      await query<{ identity: string; definition: string }>(`
        SELECT c.relname AS identity, pg_catalog.pg_get_indexdef(c.oid) AS definition
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'stash_reinstall_test'
          AND c.relname IN ('records_encrypted_idx', 'Records encrypted complex')
        ORDER BY c.relname
      `),
    ).toEqual(definitionsBefore)
    expect(
      await query<{ definition: string }>(`
        SELECT pg_catalog.pg_get_indexdef(
          'stash_reinstall_test."Records encrypted complex"'::regclass
        ) AS definition
      `),
    ).toEqual([
      {
        definition: expect.stringMatching(
          /CREATE UNIQUE INDEX.*INCLUDE \(id\).*fillfactor='80'.*WHERE \(id > 0\)/,
        ),
      },
    ])
  }, 180_000)

  /**
   * `format_type()` omits the schema whenever the type is visible on the
   * current search_path, while the identities parsed out of the bundle always
   * carry the qualification the bundle wrote. Read the catalogue with
   * `format_type()` and every bundle-owned operator and cast falls out of its
   * ownership exemption the moment a connection names `eql_v3` — and the
   * installer refuses on a healthy database, listing EQL's own operators as
   * customer-owned objects. Only a live server shows this: the sensitivity is
   * in `format_type()`, not in our SQL.
   */
  it("exempts the bundle's own operators and casts when the EQL schemas are on the search_path", async () => {
    const expected = parseExpectedSurface(loadBundledEqlSql())
    const rows = await queryOn<{
      dependency_kind: string
      identity: string
    }>(withEqlSearchPath(DATABASE_URL ?? ''), lifecycleDependenciesSql, [
      expected.operators,
      expected.casts,
    ])
    const unsafe = rows
      .filter((row) => row.dependency_kind !== 'index')
      .map((row) => row.identity)

    // Reported as a count plus a sample: the pre-fix failure is ~600 rows, and
    // a bare array comparison buries the count that identifies the bug.
    expect({ count: unsafe.length, sample: unsafe.slice(0, 3) }).toEqual({
      count: 0,
      sample: [],
    })
  }, 60_000)

  /**
   * The negative control for the test above. An empty result proves nothing on
   * its own — it is also what an EMPTY dependency graph looks like. Withhold
   * exactly the operators the bundle declares with a `pg_catalog` operand
   * (`text`, `text[]`, `jsonb`, `jsonpath`, `integer` — the parser spells those
   * bare, with no schema) and they must reappear as `unsafe`. That is what
   * pins the other half of the rule: qualifying every operand unconditionally
   * would spell these `pg_catalog.text` and silently break their exemption in
   * the direction this test, not the one above, can see.
   */
  it('exempts operators with a bare pg_catalog operand, and only because of the match', async () => {
    const expected = parseExpectedSurface(loadBundledEqlSql())
    const hasBareOperand = (identity: string) =>
      identity
        .slice(identity.indexOf('(') + 1, -1)
        .split(', ')
        .some((operand) => operand !== 'none' && !operand.includes('.'))
    const withheld = expected.operators.filter(hasBareOperand)
    expect(withheld.length).toBeGreaterThan(0)

    const rows = await queryOn<{ dependency_kind: string; identity: string }>(
      withEqlSearchPath(DATABASE_URL ?? ''),
      lifecycleDependenciesSql,
      [expected.operators.filter((o) => !hasBareOperand(o)), expected.casts],
    )

    expect(rows.filter((row) => row.dependency_kind !== 'index')).toHaveLength(
      withheld.length,
    )
  }, 60_000)

  it('installs over a connection whose search_path names the EQL schemas', async () => {
    await query(`
      CREATE INDEX records_encrypted_idx
        ON stash_reinstall_test.records (eql_v3.eq_term(encrypted));
    `)
    await expect(
      new EQLInstaller({
        databaseUrl: withEqlSearchPath(DATABASE_URL ?? ''),
      }).install(),
    ).resolves.toEqual({ deferredGrantsSql: null })
  }, 180_000)

  /**
   * A partitioned index is `relkind = 'I'`, its per-partition children are
   * separate `relkind = 'i'` rows, and the parent only becomes `indisvalid`
   * once every child has been ATTACHed. Recreating the captured definitions
   * and stopping there leaves the parent invalid forever.
   *
   * Two levels deep on purpose: an intermediate partitioned index is both a
   * parent and a child. `INDEX_STATE_SQL` proves refusal preserves every name,
   * definition, validity flag and attachment rather than partially rebuilding
   * the tree.
   */
  it('refuses a partitioned index tree before mutation', async () => {
    await query(`
      CREATE TABLE stash_reinstall_test.partitioned_records (
        id integer, encrypted public.eql_v3_text_eq NOT NULL
      ) PARTITION BY RANGE (id);
      CREATE TABLE stash_reinstall_test.partitioned_records_a
        PARTITION OF stash_reinstall_test.partitioned_records
        FOR VALUES FROM (0) TO (100) PARTITION BY RANGE (id);
      CREATE TABLE stash_reinstall_test.partitioned_records_a1
        PARTITION OF stash_reinstall_test.partitioned_records_a
        FOR VALUES FROM (0) TO (50);
      CREATE TABLE stash_reinstall_test.partitioned_records_b
        PARTITION OF stash_reinstall_test.partitioned_records
        FOR VALUES FROM (100) TO (200);
      CREATE INDEX partitioned_encrypted_idx
        ON stash_reinstall_test.partitioned_records (eql_v3.eq_term(encrypted));
      INSERT INTO stash_reinstall_test.partitioned_records VALUES
        (1, '{"v":3,"i":{},"c":"ciphertext","hm":"term"}'::jsonb),
        (150, '{"v":3,"i":{},"c":"ciphertext","hm":"term"}'::jsonb);
    `)
    const before = await query<Record<string, unknown>>(INDEX_STATE_SQL)
    // The fixture only means anything if Postgres really built the tree.
    expect(
      before.filter((row) => row.relkind === 'I').map((row) => row.identity),
    ).toEqual([
      'stash_reinstall_test.partitioned_encrypted_idx',
      'stash_reinstall_test.partitioned_records_a_eq_term_idx',
    ])

    await expect(
      new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install(),
    ).rejects.toThrow(/reinstall refused.*partitioned_encrypted_idx/is)

    expect(await query<Record<string, unknown>>(INDEX_STATE_SQL)).toEqual(
      before,
    )
    expect(
      await query<{ count: number }>(
        'SELECT count(*)::int AS count FROM stash_reinstall_test.partitioned_records',
      ),
    ).toEqual([{ count: 2 }])
  }, 180_000)

  /**
   * `pg_advisory_xact_lock` waits forever. A concurrent install, or a session that
   * died holding the lock, then makes the command hang with no output —
   * indistinguishable from a network stall.
   */
  it('refuses instead of hanging when another session holds the lifecycle lock', async () => {
    const { default: pg } = await import('pg')
    const holder = new pg.Client({ connectionString: DATABASE_URL })
    const blocked = new pg.Client({ connectionString: DATABASE_URL })
    await holder.connect()
    await blocked.connect()
    try {
      // A regression here is a HANG, not a failure — a blocking
      // `pg_advisory_xact_lock` never returns, the `finally` below never runs, and
      // the leaked lock then blocks every later `install()` in this file. The
      // timeout turns that into a failed assertion. It is inert once the
      // acquire polls with `pg_try_advisory_xact_lock`, which never waits.
      await blocked.query("SET statement_timeout = '10s'")
      await holder.query('BEGIN')
      await holder.query(
        "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('cipherstash.eql.lifecycle'))",
      )
      await blocked.query('BEGIN')

      // An explicit short budget: the behaviour under test is "refuses rather
      // than hangs", which does not depend on how long the wait is, and the
      // production default is deliberately a minute. The default's own
      // property — that an ordinary queued install still succeeds — is the
      // next test.
      await expect(acquireLifecycleLock(blocked, 1_000)).rejects.toThrow(
        /another EQL lifecycle operation is in progress/i,
      )
      await blocked.query('ROLLBACK')
      await holder.query('COMMIT')
      await blocked.query('BEGIN')
      await expect(acquireLifecycleLock(blocked)).resolves.toBeUndefined()
      await blocked.query('COMMIT')
    } finally {
      await blocked.query('ROLLBACK').catch(() => {})
      await holder.query('ROLLBACK').catch(() => {})
      await blocked.end().catch(() => undefined)
      await holder.end().catch(() => undefined)
    }
  }, 30_000)

  /**
   * The other half of the lock change, and the one that bites. Bounding the
   * wait converts "hangs forever" into a message — but bound it too tightly and
   * ordinary queueing becomes a failure, because what holds the lock is a whole
   * install (`DROP SCHEMA … CASCADE` plus ~3,000 objects, 10-30s here). A
   * five-second budget looked generous and broke exactly this: two installs
   * back to back, the second refused. The waiter must still win.
   */
  it('queues a second concurrent install instead of refusing it', async () => {
    const results = await Promise.all([
      new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install(),
      new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install(),
    ])
    expect(results).toEqual([
      { deferredGrantsSql: null },
      { deferredGrantsSql: null },
    ])
  }, 180_000)

  it('restores schemas, data, column identity, and indexes when install fails after DROP SCHEMA', async () => {
    await query(`CREATE INDEX records_encrypted_idx
      ON stash_reinstall_test.records (eql_v3.eq_term(encrypted))`)
    const before = await query<{
      version: string
      table_oid: string
      column_number: number
      column_type_oid: string
      value: unknown
      index_definition: string
    }>(`
      SELECT eql_v3.version() AS version,
             c.oid::text AS table_oid,
             a.attnum AS column_number,
             a.atttypid::text AS column_type_oid,
             r.encrypted::jsonb AS value,
             pg_catalog.pg_get_indexdef('stash_reinstall_test.records_encrypted_idx'::regclass)
               AS index_definition
      FROM stash_reinstall_test.records r
      JOIN pg_catalog.pg_class c ON c.oid = 'stash_reinstall_test.records'::regclass
      JOIN pg_catalog.pg_attribute a
        ON a.attrelid = c.oid AND a.attname = 'encrypted'
      WHERE r.id = 1
    `)
    await query(`
      CREATE FUNCTION stash_reinstall_test.reject_schema_create()
      RETURNS event_trigger LANGUAGE plpgsql AS
      'BEGIN RAISE EXCEPTION ''forced installer failure after DROP SCHEMA''; END';
      CREATE EVENT TRIGGER stash_reinstall_reject_create
        ON ddl_command_start WHEN TAG IN ('CREATE SCHEMA')
        EXECUTE FUNCTION stash_reinstall_test.reject_schema_create();
    `)
    try {
      await expect(
        new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install(),
      ).rejects.toThrow(/forced installer failure after DROP SCHEMA/)
    } finally {
      await query('DROP EVENT TRIGGER IF EXISTS stash_reinstall_reject_create')
    }
    expect(
      await query<{
        version: string
        table_oid: string
        column_number: number
        column_type_oid: string
        value: unknown
        index_definition: string
      }>(`
        SELECT eql_v3.version() AS version,
               c.oid::text AS table_oid,
               a.attnum AS column_number,
               a.atttypid::text AS column_type_oid,
               r.encrypted::jsonb AS value,
               pg_catalog.pg_get_indexdef('stash_reinstall_test.records_encrypted_idx'::regclass)
                 AS index_definition
        FROM stash_reinstall_test.records r
        JOIN pg_catalog.pg_class c ON c.oid = 'stash_reinstall_test.records'::regclass
        JOIN pg_catalog.pg_attribute a
          ON a.attrelid = c.oid AND a.attname = 'encrypted'
        WHERE r.id = 1
      `),
    ).toEqual(before)
  }, 180_000)

  it.each([
    {
      name: 'RLS policy',
      identity: 'encrypted_visible',
      setup: `
        ALTER TABLE stash_reinstall_test.records ENABLE ROW LEVEL SECURITY;
        CREATE POLICY encrypted_visible ON stash_reinstall_test.records
          USING (eql_v3.eq_term(encrypted) IS NOT NULL);
      `,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_policy WHERE polname = 'encrypted_visible'`,
    },
    {
      name: 'view',
      identity: 'encrypted_terms',
      setup: `CREATE VIEW stash_reinstall_test.encrypted_terms AS
        SELECT eql_v3.eq_term(encrypted) AS term FROM stash_reinstall_test.records`,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_views
        WHERE schemaname = 'stash_reinstall_test' AND viewname = 'encrypted_terms'`,
    },
    {
      name: 'check constraint',
      identity: 'encrypted_has_term',
      setup: `ALTER TABLE stash_reinstall_test.records
        ADD CONSTRAINT encrypted_has_term CHECK (eql_v3.eq_term(encrypted) IS NOT NULL)`,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_constraint
        WHERE conname = 'encrypted_has_term'`,
    },
    {
      name: 'generated column',
      identity: 'generated_term',
      setup: `ALTER TABLE stash_reinstall_test.records ADD COLUMN generated_term text
        GENERATED ALWAYS AS (eql_v3.eq_term(encrypted)::text) STORED`,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_attribute
        WHERE attrelid = 'stash_reinstall_test.records'::regclass
          AND attname = 'generated_term' AND NOT attisdropped`,
    },
    {
      name: 'trigger predicate',
      identity: 'encrypted_trigger',
      setup: `
        CREATE FUNCTION stash_reinstall_test.noop_trigger() RETURNS trigger
          LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
        CREATE TRIGGER encrypted_trigger BEFORE UPDATE ON stash_reinstall_test.records
          FOR EACH ROW WHEN (eql_v3.eq_term(NEW.encrypted) IS NOT NULL)
          EXECUTE FUNCTION stash_reinstall_test.noop_trigger();
      `,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_trigger
        WHERE tgname = 'encrypted_trigger'`,
    },
    {
      name: 'customer operator',
      identity: '===',
      setup: `CREATE OPERATOR stash_reinstall_test.=== (
        FUNCTION = eql_v3.eq,
        LEFTARG = public.eql_v3_text_eq,
        RIGHTARG = public.eql_v3_text_eq
      )`,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_operator o
        JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
        WHERE n.nspname = 'stash_reinstall_test' AND o.oprname = '==='`,
    },
    {
      name: 'operator duplicating a bundle signature in another schema',
      identity: 'stash_reinstall_test.=(',
      setup: `CREATE OPERATOR stash_reinstall_test.= (
        FUNCTION = eql_v3.eq,
        LEFTARG = public.eql_v3_text_eq,
        RIGHTARG = public.eql_v3_text_eq
      )`,
      remains: `SELECT count(*)::int AS count FROM pg_catalog.pg_operator o
        JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
        WHERE n.nspname = 'stash_reinstall_test' AND o.oprname = '='
          AND o.oprleft = 'public.eql_v3_text_eq'::regtype
          AND o.oprright = 'public.eql_v3_text_eq'::regtype`,
    },
  ])(
    'refuses before mutation for a customer-owned $name',
    async ({ setup, identity, remains }) => {
      await query(setup)
      const versionBefore = await query<{ version: string }>(
        'SELECT eql_v3.version() AS version',
      )

      await expect(
        new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install(),
      ).rejects.toThrow(
        new RegExp(
          `refused before making changes.*${identity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`,
          's',
        ),
      )

      expect(
        await query<{ version: string }>('SELECT eql_v3.version() AS version'),
      ).toEqual(versionBefore)
      expect(await query<{ count: number }>(remains)).toEqual([{ count: 1 }])
    },
    180_000,
  )

  it('names every view in a dependent chain, not the rewrite rule', async () => {
    // Only chain_1 references EQL. chain_2 and chain_3 reach it through the
    // view above them, and CASCADE takes all three -- but a view's dependency
    // on an EQL function is recorded against its _RETURN rule, and nothing in
    // pg_depend leads back out of a rule to its view. Before the walk carried
    // that edge, the refusal named `"_RETURN" on ...chain_1` and mentioned no
    // view at all, understating what was about to be destroyed by two.
    await query(`CREATE VIEW stash_reinstall_test.chain_1 AS
      SELECT eql_v3.eq_term(encrypted) AS term FROM stash_reinstall_test.records`)
    await query(
      'CREATE VIEW stash_reinstall_test.chain_2 AS SELECT term FROM stash_reinstall_test.chain_1',
    )
    await query(
      'CREATE VIEW stash_reinstall_test.chain_3 AS SELECT term FROM stash_reinstall_test.chain_2',
    )

    const failure = await new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' })
      .install()
      .then(() => null)
      .catch((error: unknown) =>
        error instanceof Error ? error.message : String(error),
      )

    expect(failure).toMatch(/refused before making changes/)
    expect(failure).toContain('stash_reinstall_test.chain_1')
    expect(failure).toContain('stash_reinstall_test.chain_2')
    expect(failure).toContain('stash_reinstall_test.chain_3')
    // The rule and the row/array types name the same casualties the views do.
    expect(failure).not.toContain('_RETURN')
    expect(failure).not.toContain('chain_1[]')
  }, 180_000)
})
