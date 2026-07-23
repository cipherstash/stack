import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

// The bench exists to prove the functional-index path engages. An index whose
// expression is merely "a term extractor for the right column" satisfies
// `CREATE INDEX` and satisfies the db-only smoke test's `pg_indexes` check, and
// is still never used — the planner only matches an index against the
// expression the operator INLINES TO. `eql_v3.ste_vec(enc_jsonb)` was exactly
// that: a valid, buildable, permanently-dead index, because `@>` on
// `eql_v3_json_search` inlines to `eql_v3.to_ste_vec_query(a)::jsonb`.
//
// Every EQL v3 operator wrapper is `LANGUAGE sql IMMUTABLE STRICT` with a
// single-SELECT body, which is what makes it inlinable — and Postgres runs the
// same simplification over stored index expressions, so the two meet only if
// the index names the function in the operator's BODY.
//
// This test reads the vendored EQL bundle (the same SQL `stash eql install`
// applies) and pins each bench index to the function its operator actually
// lowers to. It needs no database and no credentials, which is the point: the
// bench's own EXPLAIN assertions require CipherStash credentials and never run
// in CI.

const require = createRequire(resolve(REPO_ROOT, 'packages/cli/package.json'))

/** The EQL v3 bundle `stash eql install --eql-version 3` applies. */
function bundleSql() {
  const pkgJson = require.resolve('@cipherstash/eql/package.json')
  return readFileSync(
    resolve(dirname(pkgJson), 'dist/sql/cipherstash-encrypt.sql'),
    'utf8',
  )
}

/**
 * The body of one `CREATE FUNCTION` in the bundle, from its signature line to
 * the `$$` that closes it.
 */
function functionBody(sql, signature) {
  const start = sql.indexOf(signature)
  expect(start, `bundle has no ${signature}`).toBeGreaterThan(-1)
  const bodyStart = sql.indexOf('$$', start)
  const bodyEnd = sql.indexOf('$$', bodyStart + 2)
  return sql.slice(bodyStart + 2, bodyEnd)
}

/** `eql_v3.<name>(` calls appearing in a SQL fragment. */
function eqlCalls(fragment) {
  return [...fragment.matchAll(/eql_v3\.([a-z_0-9]+)\s*\(/g)].map((m) => m[1])
}

const SCHEMA_SQL = readFileSync(
  resolve(REPO_ROOT, 'packages/bench/sql/schema.sql'),
  'utf8',
)

/** `CREATE INDEX <name> ... (<expression>)` pairs from the bench fixture. */
function benchIndexes() {
  const found = new Map()
  for (const m of SCHEMA_SQL.matchAll(
    /CREATE INDEX\s+(\w+)\s+ON bench USING \w+\s*\(([\s\S]*?)\);/g,
  )) {
    found.set(m[1], m[2].trim())
  }
  return found
}

/**
 * Each bench index, and the operator wrapper whose inlined body it has to
 * match. Signatures are the `query_<domain>` overloads — the narrowed query
 * term is what the Drizzle adapter casts its operand to.
 */
const INDEX_CONTRACTS = [
  {
    index: 'bench_text_hmac_idx',
    operator:
      'CREATE FUNCTION eql_v3.eq(a public.eql_v3_text_search, b eql_v3.query_text_search)',
    inlinesTo: 'eq_term',
  },
  {
    index: 'bench_text_bloom_idx',
    operator:
      'CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_search, b eql_v3.query_text_search)',
    inlinesTo: 'match_term',
  },
  {
    index: 'bench_jsonb_stevec_idx',
    operator:
      'CREATE FUNCTION eql_v3."@>"(a public.eql_v3_json_search, b eql_v3.query_json)',
    inlinesTo: 'to_ste_vec_query',
  },
]

describe('bench index expressions match the EQL v3 operator lowering', () => {
  const sql = bundleSql()
  const indexes = benchIndexes()

  it('parses all three bench indexes (guards a silently-empty regex)', () => {
    expect([...indexes.keys()].sort()).toEqual(
      INDEX_CONTRACTS.map((c) => c.index).sort(),
    )
  })

  it.each(
    INDEX_CONTRACTS,
  )('$index is built on the function $operator inlines to', ({
    index,
    operator,
    inlinesTo,
  }) => {
    const body = functionBody(sql, operator)

    // The operator really does lower to this function — if the bundle
    // changes shape, this fails here rather than silently passing the
    // schema check below against a stale assumption.
    expect(
      eqlCalls(body),
      `${operator} no longer calls eql_v3.${inlinesTo}`,
    ).toContain(inlinesTo)

    expect(
      eqlCalls(indexes.get(index)),
      `${index} must index eql_v3.${inlinesTo}(...) — the expression the ` +
        'operator inlines to — or the planner can never match it',
    ).toEqual([inlinesTo])
  })

  it('the operator wrappers are inlinable (LANGUAGE sql IMMUTABLE STRICT)', () => {
    for (const { operator } of INDEX_CONTRACTS) {
      const start = sql.indexOf(operator)
      const header = sql.slice(start, sql.indexOf('$$', start))
      // A plpgsql or VOLATILE wrapper would never be inlined, so no functional
      // index on its body could ever engage.
      expect(header.toLowerCase(), operator).toMatch(/language sql/)
      expect(header.toLowerCase(), operator).toMatch(/immutable/)
    }
  })
})
