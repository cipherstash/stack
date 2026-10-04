/**
 * Live-Supabase-CLI coverage for the generated EQL install migration.
 *
 * Everything else about `eql migration --supabase` is tested against the
 * filesystem, which is right for the writer's control flow and useless for the
 * only question that actually matters: what the *Supabase CLI* does with the
 * file we wrote. The unit suite's ordering test sorts two filenames in a
 * tmpdir — it pins that our name sorts second and says nothing about whether
 * `db push` applies it, refuses it, or ignores it.
 *
 * That gap mattered. The `--force` re-apply guidance this command prints (and
 * ships to customers in `skills/stash-cli` and `skills/stash-supabase`) was
 * derived by reading supabase/cli's Go source, and reading got one detail
 * wrong — see `needs --include-all only when the install is not the newest
 * migration` below.
 *
 * `db push --db-url` needs no Docker and no linked project (the flag is
 * mutually exclusive with `--linked`/`--local`), so a bare Postgres cluster is
 * enough to exercise the real binary. What that still leaves unproven is
 * `db reset` — it removes the container and volume, so it needs the full local
 * stack — and the PostgREST HTTP round-trip. The grants are covered here one
 * layer down, via `SET ROLE`, which is exactly what PostgREST does after
 * connecting as `authenticator`.
 *
 * Gated on both env vars so the default `pnpm test` stays green. Locally:
 *
 *   initdb -D /tmp/sbpg -U postgres
 *   pg_ctl -D /tmp/sbpg -o "-p 55444 -k /tmp" -l /tmp/sbpg.log start
 *   createdb -h 127.0.0.1 -p 55444 -U postgres sbtest
 *   psql -h 127.0.0.1 -p 55444 -U postgres -d sbtest \
 *     -c "CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN;"
 *   export STASH_TEST_SUPABASE_DB_URL='postgresql://postgres@127.0.0.1:55444/sbtest?sslmode=disable'
 *   export STASH_TEST_SUPABASE_CLI='npx --yes supabase@2.111.0'
 *
 * The three roles must exist before anything here runs: the emitted SQL grants
 * to `anon`/`authenticated`/`service_role` and sets default privileges FOR ROLE
 * `postgres`, none of which a bare cluster has. On a real Supabase project they
 * are all present — this is a fixture requirement, not a product gap.
 *
 * `sslmode=disable` is likewise a bare-cluster detail: the CLI negotiates TLS
 * by default and fails with `The server does not support SSL connections`
 * against a stock `initdb`.
 */

import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest'
import { buildEqlV3MigrationSql } from '../migration.js'
import { writeSupabaseEqlMigration } from '../supabase-migration.js'

const DATABASE_URL = process.env.STASH_TEST_SUPABASE_DB_URL
const CLI = process.env.STASH_TEST_SUPABASE_CLI
const describeLive = DATABASE_URL && CLI ? describe : describe.skip

/**
 * Pushing the real ~2.6 MB bundle takes a few seconds per call, and several
 * tests push more than once.
 */
const LIVE_TIMEOUT = 120_000

/** A migration the install must land *after*, so the ledger has prior state. */
const EARLIER_VERSION = '20260101000000'

describeLive('eql migration --supabase — live Supabase CLI', () => {
  let projectDir: string
  let migrationsDir: string

  // The CLI is given as a command line ("npx --yes supabase@2.111.0" or a bare
  // binary path), so it splits into argv rather than going through a shell —
  // the connection string carries credentials and must never be word-split or
  // interpreted.
  function supabase(...args: string[]): {
    status: number | null
    stdout: string
    stderr: string
  } {
    const parts = (CLI as string).split(/\s+/).filter(Boolean)
    const result = spawnSync(
      parts[0],
      [...parts.slice(1), ...args, '--db-url', DATABASE_URL as string],
      { cwd: projectDir, encoding: 'utf-8', stdio: 'pipe' },
    )
    return {
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
    }
  }

  async function withClient<T>(
    fn: (q: (sql: string) => Promise<{ rows: unknown[][] }>) => Promise<T>,
  ): Promise<T> {
    const { default: pg } = await import('pg')
    const client = new pg.Client({ connectionString: DATABASE_URL })
    await client.connect()
    try {
      return await fn(async (sql: string) => {
        const result = await client.query({ text: sql, rowMode: 'array' })
        return { rows: result.rows as unknown[][] }
      })
    } finally {
      await client.end().catch(() => undefined)
    }
  }

  /**
   * Back to a database that has never seen EQL, or these tests.
   *
   * Drops the ledger, because a leftover `schema_migrations` row makes the next
   * push a no-op — which looks exactly like the bug the `--force` test checks
   * for. And drops `public` wholesale rather than naming the tables and marker
   * schemas each test creates: the EQL bundle puts its column domains in
   * `public` too, and an enumerated list silently rots the first time someone
   * adds a test. Getting this wrong does not fail loudly — the suite passes
   * against a fresh cluster and fails on the second run, which is the worst
   * shape a test can have.
   */
  async function resetDatabase(): Promise<void> {
    await withClient(async (q) => {
      await q('DROP SCHEMA IF EXISTS supabase_migrations CASCADE')
      await q('DROP SCHEMA IF EXISTS eql_v3 CASCADE')
      await q('DROP SCHEMA IF EXISTS eql_v3_internal CASCADE')
      await q('DROP SCHEMA IF EXISTS cipherstash CASCADE')
      // Marker schemas the re-apply and temp-file tests use as canaries.
      await q('DROP SCHEMA IF EXISTS force_marker CASCADE')
      await q('DROP SCHEMA IF EXISTS leaked_temp_file CASCADE')
      await q('DROP SCHEMA IF EXISTS public CASCADE')
      await q('CREATE SCHEMA public')
      // Re-granted explicitly: a hand-created `public` does not inherit the
      // grants initdb gives the one it ships, and the emitted migration's
      // `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public` needs the
      // roles to be able to reach it.
      await q('GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC')
    })
  }

  /** Write the real install SQL, through the real writer, into the project. */
  async function writeInstall(options: { force?: boolean; now?: Date } = {}) {
    return await writeSupabaseEqlMigration({
      migrationsDir,
      sql: buildEqlV3MigrationSql({ supabase: true }),
      ...options,
    })
  }

  beforeEach(async () => {
    projectDir = mkdtempSync(join(tmpdir(), 'stash-supabase-push-'))
    migrationsDir = join(projectDir, 'supabase', 'migrations')
    // `db push` resolves `<cwd>/supabase/migrations` and wants the project
    // marker beside it; both have to exist before the CLI is invoked.
    mkdirSync(migrationsDir, { recursive: true })
    writeFileSync(
      join(projectDir, 'supabase', 'config.toml'),
      'project_id = "stash-live-test"\n',
    )
    await resetDatabase()
  })

  afterEach(() => {
    rmSync(projectDir, { recursive: true, force: true })
  })

  afterAll(async () => {
    await resetDatabase()
  })

  /**
   * Seed one applied migration so the install is never the only thing in the
   * ledger — "sorts after what is already applied" is only meaningful when
   * something already is.
   */
  function seedApplied(): void {
    writeFileSync(
      join(migrationsDir, `${EARLIER_VERSION}_users.sql`),
      'CREATE TABLE users (id serial primary key);\n',
    )
  }

  it(
    'applies the generated install through the real CLI, with no --include-all',
    async () => {
      seedApplied()
      const written = await writeInstall()

      const push = supabase('db', 'push')
      expect(push.status, push.stdout + push.stderr).toBe(0)
      expect(push.stdout).toContain(`${written.version}_cipherstash_eql.sql`)

      await withClient(async (q) => {
        const ledger = await q(
          'SELECT version FROM supabase_migrations.schema_migrations ORDER BY version',
        )
        expect(ledger.rows.map((r) => r[0])).toEqual([
          EARLIER_VERSION,
          written.version,
        ])

        // The install really ran, rather than the ledger row being written for
        // a body Postgres rejected. Also the only proof that the CLI's
        // statement splitter survives the bundle's dollar-quoted function
        // bodies — ~2.6 MB of them.
        const schemas = await q(
          "SELECT nspname FROM pg_namespace WHERE nspname IN ('eql_v3','eql_v3_internal','cipherstash') ORDER BY 1",
        )
        expect(schemas.rows.map((r) => r[0])).toEqual([
          'cipherstash',
          'eql_v3',
          'eql_v3_internal',
        ])
      })
    },
    LIVE_TIMEOUT,
  )

  it(
    'grants the Supabase roles through the emitted file, not just through `eql install`',
    async () => {
      await writeInstall()
      const push = supabase('db', 'push')
      expect(push.status, push.stdout + push.stderr).toBe(0)

      // `SET ROLE anon` is what PostgREST does after connecting as
      // `authenticator`, so this is the same privilege check a request makes —
      // one layer below the HTTP round-trip the Docker suite covers, and
      // against the grants carried INSIDE the generated migration rather than
      // the ones `eql install --direct` applies.
      await withClient(async (q) => {
        const privileges = await q(
          "SELECT has_schema_privilege('anon','eql_v3','USAGE'), has_schema_privilege('anon','eql_v3_internal','USAGE')",
        )
        expect(privileges.rows[0]).toEqual([true, true])

        await q('SET ROLE anon')
        const call = await q(
          `SELECT eql_v3.ciphertext('{"c":"x","i":{"t":"t","c":"c"},"v":2}'::jsonb)`,
        )
        expect(call.rows[0][0]).toBe('x')
      })
    },
    LIVE_TIMEOUT,
  )

  it(
    'refuses an out-of-order install rather than silently skipping it',
    async () => {
      seedApplied()
      // Apply the seed on its own first, so the back-dated install lands below
      // something the remote has already recorded.
      expect(supabase('db', 'push').status).toBe(0)

      await writeInstall({ now: new Date('2025-01-01T00:00:00.000Z') })

      const push = supabase('db', 'push')
      expect(push.status).not.toBe(0)
      const output = push.stdout + push.stderr
      expect(output).toContain(
        'Found local migration files to be inserted before the last migration on remote database.',
      )
      expect(output).toContain('--include-all')

      // Aborted, not partially applied: the whole push is rejected before any
      // file runs. This is the behaviour the timestamped version exists to
      // avoid, and it is NOT the "silently skipped" one an earlier comment in
      // this codebase claimed.
      await withClient(async (q) => {
        const schemas = await q(
          "SELECT count(*) FROM pg_namespace WHERE nspname = 'eql_v3'",
        )
        expect(Number(schemas.rows[0][0])).toBe(0)
      })
    },
    LIVE_TIMEOUT,
  )

  it(
    'does not re-apply a --force-replaced file: the push is a silent no-op',
    async () => {
      const written = await writeInstall()
      expect(supabase('db', 'push').status).toBe(0)

      // Replace the body with something whose effect is trivially detectable.
      // A real `--force` run rewrites the bundle; the question here is only
      // whether the CLI notices a content change at an applied version.
      await writeSupabaseEqlMigration({
        migrationsDir,
        sql: 'CREATE SCHEMA force_marker;',
        force: true,
      })

      const push = supabase('db', 'push')
      expect(push.status, push.stdout + push.stderr).toBe(0)
      expect(push.stdout).toMatch(/up to date/i)

      // The heart of it: pending is computed by version, never by content, so
      // the replaced body never runs. Any guidance that tells a user to
      // re-apply a `--force`d install with a plain `db push` is wrong, and this
      // is the assertion that says so.
      await withClient(async (q) => {
        const marker = await q(
          "SELECT count(*) FROM pg_namespace WHERE nspname = 'force_marker'",
        )
        expect(Number(marker.rows[0][0])).toBe(0)
      })

      // And the recipe we print instead does work: clear the ledger row, then
      // push. `migration repair` touches the tracking table only.
      const repair = supabase(
        'migration',
        'repair',
        '--status',
        'reverted',
        written.version as string,
      )
      expect(repair.status, repair.stdout + repair.stderr).toBe(0)

      const rePush = supabase('db', 'push')
      expect(rePush.status, rePush.stdout + rePush.stderr).toBe(0)
      await withClient(async (q) => {
        const marker = await q(
          "SELECT count(*) FROM pg_namespace WHERE nspname = 'force_marker'",
        )
        expect(Number(marker.rows[0][0])).toBe(1)
      })
    },
    LIVE_TIMEOUT,
  )

  it(
    'needs --include-all only when the install is not the newest migration',
    async () => {
      // The correction to the shipped recipe. After `migration repair --status
      // reverted`, whether the follow-up push needs `--include-all` depends
      // entirely on where the reverted version sits: at the tail it is just
      // pending and a plain push takes it, and only a version with applied
      // migrations ABOVE it is the "gap in the middle" that trips
      // ErrMissingRemote. The greenfield flow puts encrypted-column migrations
      // after the install, which is exactly the gap case — so the flag belongs
      // in the guidance, but as a condition rather than a rule.
      seedApplied()
      const written = await writeInstall()
      expect(supabase('db', 'push').status).toBe(0)

      // Install is newest: reverting it leaves a tail, not a gap.
      expect(
        supabase(
          'migration',
          'repair',
          '--status',
          'reverted',
          written.version as string,
        ).status,
      ).toBe(0)
      const tailPush = supabase('db', 'push')
      expect(tailPush.status, tailPush.stdout + tailPush.stderr).toBe(0)
      expect(tailPush.stdout).toContain('cipherstash_eql.sql')

      // Now give it a successor, so reverting the install leaves a hole.
      writeFileSync(
        join(migrationsDir, '20270101000000_later.sql'),
        'CREATE TABLE later_table (id int);\n',
      )
      expect(supabase('db', 'push').status).toBe(0)
      expect(
        supabase(
          'migration',
          'repair',
          '--status',
          'reverted',
          written.version as string,
        ).status,
      ).toBe(0)

      const gapPush = supabase('db', 'push')
      expect(gapPush.status).not.toBe(0)
      expect(gapPush.stdout + gapPush.stderr).toContain(
        'Found local migration files to be inserted before the last migration on remote database.',
      )

      const includeAll = supabase('db', 'push', '--include-all')
      expect(includeAll.status, includeAll.stdout + includeAll.stderr).toBe(0)
    },
    LIVE_TIMEOUT,
  )

  it(
    'ignores a leaked temp file instead of applying a half-written one',
    async () => {
      const written = await writeInstall()
      expect(supabase('db', 'push').status).toBe(0)

      // The exact name the atomic write uses between `writeFile` and `rename`,
      // holding SQL that must never run.
      writeFileSync(
        join(migrationsDir, `.${written.version}_cipherstash_eql.sql.tmp`),
        'CREATE SCHEMA leaked_temp_file;',
      )

      const push = supabase('db', 'push')
      expect(push.status, push.stdout + push.stderr).toBe(0)
      // Inert, but not invisible: the CLI reads the whole directory and reports
      // every name that fails `^([0-9]+)_(.*)\.sql$`, on every push and reset
      // until someone deletes it.
      expect(push.stdout + push.stderr).toContain(
        'file name must match pattern',
      )

      await withClient(async (q) => {
        const leaked = await q(
          "SELECT count(*) FROM pg_namespace WHERE nspname = 'leaked_temp_file'",
        )
        expect(Number(leaked.rows[0][0])).toBe(0)
      })
    },
    LIVE_TIMEOUT,
  )
})
