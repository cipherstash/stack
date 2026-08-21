import { releaseManifest } from '@cipherstash/eql/sql'
import type pg from 'pg'
import { createPgClient, TlsVerificationError } from '@/db/client.js'
import { EQL_V3_INTERNAL_SCHEMA_NAME, EQL_V3_SCHEMA_NAME } from './grants.js'
import { loadBundledEqlSql, SUPPORTED_PGCRYPTO_SCHEMAS } from './index.js'
import {
  classifyOreState,
  describeOreState,
  ORE_OPCLASS_PRESENT_EXPR,
  type OreSurfaceState,
} from './ore.js'

/**
 * `stash eql verify` — assert that the installed EQL surface is complete and
 * coherent, independent of any application schema (#890).
 *
 * `isInstalled()` is a presence test (do the two schemas exist) and
 * `eql validate` checks the columns an application declared. Neither notices a
 * partial install where the domains landed but some of their supporting
 * functions or operators did not — that failure mode reports success at
 * install time and errors at query time, on a specific predicate.
 *
 * The manifest of what a complete install looks like is not hand-maintained:
 * it is parsed out of the pinned bundle itself ({@link parseExpectedSurface}),
 * so a bundle upgrade updates the expectation automatically. The one seam this
 * leaves is the bundle's own conditional objects — the ORE operator class the
 * bundle skips for non-superusers, and the poison fallback it installs in its
 * place — which the parser cannot see (they live inside DO blocks) and the
 * differ therefore models explicitly ({@link OreSurfaceState}).
 */

/** Everything the pinned bundle installs unconditionally. */
export interface ExpectedSurface {
  /** The bundle's own version string (from the release manifest). */
  eqlVersion: string
  /** The two EQL schemas. */
  schemas: string[]
  /** Qualified domain names, e.g. `public.eql_v3_double_ord`. */
  domains: string[]
  /** Qualified composite type names (the ORE term/block types). */
  types: string[]
  /**
   * Distinct type-only signatures per qualified routine name (functions and
   * aggregates share `pg_proc`, so they share this map). Quoted names are
   * stored unquoted: `eql_v3_internal.-`, matching `pg_proc.proname`. Each
   * signature is the comma-joined argument type list (`''` for zero-arg), in
   * the same spelling {@link InstalledSurface.functionSignatures} produces —
   * signatures, not counts, so a stale same-name function cannot mask a
   * missing overload.
   */
  functions: Map<string, string[]>
  /** Operator identities: `<name> (<leftarg>, <rightarg>)`, lowercase. */
  operators: string[]
  /** Casts as `<source> AS <target>`. */
  casts: string[]
  /**
   * The ORE-carrying domains (`*_ord_ore` / `*_search_ore`). When the bundle
   * cannot create the ORE operator class (non-superuser), it poisons exactly
   * these with an always-raising `eql_ore_unavailable` CHECK.
   */
  oreDomains: string[]
}

/**
 * How the ORE half of the install reads. Defined in `./ore.js`, which owns the
 * whole ORE model — the catalogue probe, the state machine, and the copy every
 * command renders — and re-exported here because `VerifyReport` carries it.
 */
export type { OreSurfaceState }

export interface SurfaceFinding {
  severity: 'damage' | 'warning' | 'expected'
  kind:
    | 'schema'
    | 'extension'
    | 'version'
    | 'domain'
    | 'type'
    | 'function'
    | 'operator'
    | 'cast'
    | 'opclass'
  /**
   * The bare EQL domain this finding concerns (e.g. `eql_v3_double_ord`),
   * when one can be attributed — lets the report group per-domain.
   */
  domain?: string
  message: string
}

export interface SurfaceCounts {
  domains: { expected: number; present: number }
  types: { expected: number; present: number }
  functions: { expected: number; present: number }
  operators: { expected: number; present: number }
  casts: { expected: number; present: number }
}

export interface VerifyReport {
  /**
   * `complete` — every expected object is present (ORE either indexable or in
   * its supported fallback). `incomplete` — damage findings exist.
   * `not-installed` — the `eql_v3` schema is absent. `version-mismatch` — an
   * older/newer EQL is installed, so the pinned bundle is the wrong manifest
   * to diff against and the object-level checks were skipped.
   */
  status: 'complete' | 'incomplete' | 'not-installed' | 'version-mismatch'
  bundleVersion: string
  installedVersion: string | null
  counts: SurfaceCounts | null
  ore: {
    opclassPresent: boolean
    poisonedDomains: number
    expectedPoisoned: number
    state: OreSurfaceState
  } | null
  findings: SurfaceFinding[]
  /**
   * True ONLY when the surface was actually checked and found complete
   * (`status: 'complete'`). A `version-mismatch` — where the checks were
   * skipped — is NOT ok: "could not verify" must never read as "verified".
   */
  ok: boolean
}

// ---------------------------------------------------------------------------
// Parsing the pinned bundle into an expected surface
// ---------------------------------------------------------------------------

/**
 * Blank out every dollar-quoted body (`$$...$$`, `$tag$...$tag$`) so the
 * statement-level regexes below cannot match SQL inside function bodies or DO
 * blocks. Newlines are preserved to keep the column-0 anchors meaningful.
 *
 * This is also what keeps the bundle's conditional objects out of the
 * expected set: the ORE operator class/family and the poison fallback are
 * created inside DO blocks, so they vanish here and are modelled explicitly
 * by the differ instead.
 */
function stripDollarQuoted(sql: string): string {
  return sql.replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, (quoted) =>
    quoted.replace(/[^\n]/g, ' '),
  )
}

/** `eql_v3_internal."-"` -> `eql_v3_internal.-` (matching pg_catalog names). */
function unquoteName(raw: string): string {
  return raw.replace(/"/g, '').toLowerCase()
}

/**
 * SQL type-name aliases mapped to the canonical spelling `format_type()`
 * emits, so a future bundle writing `int8` or `timestamptz` still meets the
 * catalogue read. The current bundle only uses spellings that are already
 * canonical (`integer`, `text[]`, `jsonb`, …) — the live suite is what proves
 * that on every run, this map is the cheap safety margin for a bump.
 */
const TYPE_ALIASES: Record<string, string> = {
  int: 'integer',
  int2: 'smallint',
  int4: 'integer',
  int8: 'bigint',
  bool: 'boolean',
  float4: 'real',
  float8: 'double precision',
  decimal: 'numeric',
  timestamptz: 'timestamp with time zone',
  varchar: 'character varying',
  char: 'character',
}

function canonicalType(raw: string): string {
  const lower = raw.toLowerCase()
  const array = lower.endsWith('[]')
  const base = array ? lower.slice(0, -2) : lower
  const canonical = TYPE_ALIASES[base] ?? base
  return array ? `${canonical}[]` : canonical
}

/**
 * The multi-word SQL type names, canonically spelled. {@link argType} drops
 * the first token of a multi-token entry to skip the argument's NAME, which is
 * right for `a double precision` and wrong for an UNNAMED `double precision`,
 * where the first token is half the type (it would parse as `precision` and
 * report a phantom missing overload for the whole signature). The bundle names
 * every argument today; this set is what keeps that from being load-bearing.
 */
const MULTI_WORD_TYPES = new Set([
  'double precision',
  'character varying',
  'bit varying',
  'timestamp with time zone',
  'timestamp without time zone',
  'time with time zone',
  'time without time zone',
])

/**
 * Reduce one routine argument to its type: the bundle names every argument
 * (`a public.eql_v3_bigint`, `val jsonb`) and uses no DEFAULTs or arg modes,
 * so dropping the first token of a multi-token entry leaves the type —
 * including multi-word types, which keep their remaining tokens. A
 * single-token entry (aggregate signatures are types-only) is already a type,
 * as is an unnamed multi-word one ({@link MULTI_WORD_TYPES}).
 */
function argType(entry: string): string {
  const whole = canonicalType(entry.trim().replace(/\s+/g, ' '))
  if (MULTI_WORD_TYPES.has(whole.replace(/\[\]$/, ''))) return whole
  const tokens = entry.trim().split(/\s+/)
  return canonicalType((tokens.length > 1 ? tokens.slice(1) : tokens).join(' '))
}

/**
 * Statement kinds a `CREATE` can carry that this parser deliberately does not
 * model, each with the reason it is safe to leave out of the expected surface.
 * Anything else the handlers do not consume is a parse-time error — see
 * {@link assertEveryStatementModelled}.
 */
const UNMODELLED_STATEMENT_KINDS = new Map<string, string>([
  [
    'SCHEMA',
    'the two EQL schemas are fixed names checked directly against pg_namespace, not derived from the parse',
  ],
  [
    'EXTENSION',
    'the only extension EQL needs is pgcrypto, which the differ checks by name AND by schema — a stricter check than presence in the parse',
  ],
  [
    'INDEX',
    'an index is a performance artifact, not part of the callable surface: a missing one costs a query plan, it does not make a predicate fail',
  ],
])

/**
 * Fail loudly on any bundle statement the handlers below did not consume.
 *
 * Every regex in this parser fails OPEN: a statement whose spelling it does
 * not match simply never enters the expected surface, so `stash eql verify`
 * reports "complete" on an install missing that object — the exact silent
 * partial install the command exists to catch. A future bundle's
 * `CREATE PROCEDURE`, an indented `CREATE TYPE`, or a `CREATE OPERATOR` the
 * pattern cannot span would all narrow the check in silence.
 *
 * So: scan the same stripped SQL for statement-leading `CREATE`s and require
 * every one to be either consumed by a handler or named in
 * {@link UNMODELLED_STATEMENT_KINDS}. Consumption is tracked by byte offset,
 * which works across the raw/stripped split because {@link stripDollarQuoted}
 * replaces characters one-for-one and so preserves every offset. A bundle bump
 * that outgrows the parser now breaks this package's own test suite instead of
 * quietly shrinking what `verify` verifies.
 */
function assertEveryStatementModelled(
  stripped: string,
  consumed: Set<number>,
): void {
  for (const match of stripped.matchAll(
    /^[ \t]*(CREATE)\s+(?:OR\s+REPLACE\s+)?([A-Za-z]+)/gim,
  )) {
    const offset = match.index + match[0].indexOf(match[1])
    if (consumed.has(offset)) continue
    const kind = match[2].toUpperCase()
    if (UNMODELLED_STATEMENT_KINDS.has(kind)) continue
    const line = stripped.slice(0, offset).split('\n').length
    const statement = stripped.slice(offset).split('\n')[0].trim()
    throw new Error(
      `The EQL install SQL contains a statement the expected-surface parser does not model, at line ${line}: \`${statement}\`. Objects it creates would never be checked, so \`stash eql verify\` would report a partial install as complete. Teach \`parseExpectedSurface\` to read this form, or — if it creates nothing the verifier should check — add \`${kind}\` to \`UNMODELLED_STATEMENT_KINDS\` with the reason.`,
    )
  }
}

/** Parse the pinned install SQL into the surface it creates unconditionally. */
export function parseExpectedSurface(sql: string): ExpectedSurface {
  const stripped = stripDollarQuoted(sql)
  // Offsets of the statements the handlers below understood, for
  // {@link assertEveryStatementModelled}.
  const consumed = new Set<number>()

  // Domains are created inside `IF NOT EXISTS ... CREATE DOMAIN` DO blocks,
  // so they are read from the RAW text (any indentation) and deduped. They
  // are unconditional in effect — the guard only makes reinstalls idempotent.
  const domains = new Set<string>()
  for (const match of sql.matchAll(
    /^([ \t]*)CREATE DOMAIN\s+([\w.]+)\s+AS/gim,
  )) {
    domains.add(match[2].toLowerCase())
    consumed.add(match.index + match[1].length)
  }

  const types = new Set<string>()
  for (const match of stripped.matchAll(/^CREATE TYPE\s+([\w.]+)\s+AS/gim)) {
    types.add(match[1].toLowerCase())
    consumed.add(match.index)
  }

  // Functions and aggregates: DISTINCT type-only signatures per name (the
  // bundle re-CREATEs some signatures, which must not inflate the
  // expectation), folded into one map — they share pg_proc on the observed
  // side.
  const signatures = new Map<string, Set<string>>()
  const routinePattern =
    /^CREATE (?:OR REPLACE )?(?:FUNCTION|AGGREGATE)\s+((?:[\w]+\.)?(?:"[^"]+"|[\w]+))\s*\(([^)]*)\)/gim
  for (const match of stripped.matchAll(routinePattern)) {
    consumed.add(match.index)
    const name = unquoteName(match[1])
    const args = match[2].trim()
    const signature = args === '' ? '' : args.split(',').map(argType).join(', ')
    const existing = signatures.get(name) ?? new Set<string>()
    existing.add(signature)
    signatures.set(name, existing)
  }
  const functions = new Map<string, string[]>()
  for (const [name, sigs] of signatures) functions.set(name, [...sigs].sort())

  // Operators: identity is (name, leftarg, rightarg) — deliberately WITHOUT
  // the operator's schema. Most of the bundle's operators are created
  // unqualified, so they land in the first existing schema of the
  // install-time search_path: usually `public`, but a "$user" schema named
  // after the installing role (common on provisioned databases) legitimately
  // captures them instead. Only the six ore_block_256 comparison operators
  // are explicitly `public.`-qualified (the opclass block references them by
  // that name). Scoping the check to one schema would therefore phantom-fail
  // healthy installs — the live suite runs against exactly such a database.
  const operators = new Set<string>()
  const operatorPattern = /^CREATE OPERATOR\s+([^\s(]+)\s*\(([\s\S]*?)\);/gim
  for (const match of stripped.matchAll(operatorPattern)) {
    consumed.add(match.index)
    const name = match[1].toLowerCase().replace(/^public\./, '')
    const left = /LEFTARG\s*=\s*([\w.[\]]+)/i.exec(match[2])?.[1] ?? 'none'
    const right = /RIGHTARG\s*=\s*([\w.[\]]+)/i.exec(match[2])?.[1] ?? 'none'
    operators.add(`${name} (${canonicalType(left)}, ${canonicalType(right)})`)
  }

  const casts = new Set<string>()
  for (const match of stripped.matchAll(
    /^CREATE CAST\s*\(\s*([\w.[\]]+)\s+AS\s+([\w.[\]]+)\s*\)/gim,
  )) {
    consumed.add(match.index)
    casts.add(`${canonicalType(match[1])} AS ${canonicalType(match[2])}`)
  }

  assertEveryStatementModelled(stripped, consumed)

  const sortedDomains = [...domains].sort()
  return {
    eqlVersion: releaseManifest.eqlVersion,
    schemas: [EQL_V3_SCHEMA_NAME, EQL_V3_INTERNAL_SCHEMA_NAME],
    domains: sortedDomains,
    types: [...types].sort(),
    functions,
    operators: [...operators].sort(),
    casts: [...casts].sort(),
    oreDomains: sortedDomains.filter((domain) => domain.endsWith('_ore')),
  }
}

/** The expected surface of the pinned bundle this CLI installs. */
export function bundledExpectedSurface(): ExpectedSurface {
  // Through `loadBundledEqlSql()` rather than `readInstallSql()` directly, so
  // this shares the CLI's one digest check. `stash eql verify` compares a live
  // database against this expectation — derived from an unverified bundle it
  // would answer a different question than the one asked, and could report a
  // healthy install as broken (or the reverse) from tampered bytes alone.
  const sql = loadBundledEqlSql()
  // Deliberately outside any try: a parse failure is a bundle the parser has
  // outgrown ({@link assertEveryStatementModelled}), and its message names the
  // statement. Wrapping it in "reinstall dependencies" would send whoever hits
  // it to the one remedy that cannot help.
  return parseExpectedSurface(sql)
}

// ---------------------------------------------------------------------------
// Reading the installed surface
// ---------------------------------------------------------------------------

export interface InstalledSurface {
  eqlV3SchemaPresent: boolean
  eqlV3InternalSchemaPresent: boolean
  pgcryptoInstalled: boolean
  /** The schema pgcrypto lives in, `null` when not installed. */
  pgcryptoSchema: string | null
  installedVersion: string | null
  presentTypes: Set<string>
  /** Type-only argument signatures per qualified routine name. */
  functionSignatures: Map<string, Set<string>>
  presentOperators: Set<string>
  presentCasts: Set<string>
  oreOpclassPresent: boolean
  poisonedDomains: number
}

const SCHEMAS_SQL = `
  SELECT
    EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = '${EQL_V3_SCHEMA_NAME}') AS eql_v3_present,
    EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS eql_v3_internal_present,
    EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pgcrypto') AS pgcrypto_installed,
    (SELECT n.nspname FROM pg_catalog.pg_extension e
      JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
      WHERE e.extname = 'pgcrypto') AS pgcrypto_schema
`

/** Domains and composite types by qualified name, in one probe. */
const TYPES_SQL = `
  SELECT n.nspname || '.' || t.typname AS name
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname || '.' || t.typname = ANY($1::text[])
`

/**
 * One row per overload of an expected routine name, with its input argument
 * types rendered by `format_type` — which, under the empty `search_path` the
 * surrounding transaction pins (see {@link readInstalledSurface}), emits the
 * same spelling the parser produces: catalogue types unqualified (`integer`,
 * `text[]`), everything else schema-qualified, arrays with a `[]` suffix
 * (`eql_v3_internal.ore_block_256_term[]`, where the raw catalogue row would
 * say `_ore_block_256_term`). Signatures rather than counts, so a stale
 * same-name function cannot mask a genuinely missing overload. `proargtypes`
 * is input arguments only, which is exactly what the parsed
 * `CREATE FUNCTION`/`AGGREGATE` argument lists carry.
 */
const FUNCTION_SIGNATURES_SQL = `
  SELECT n.nspname || '.' || p.proname AS name,
         COALESCE((
           SELECT string_agg(pg_catalog.format_type(a.oid, NULL), ', ' ORDER BY a.ordinality)
           FROM unnest(p.proargtypes) WITH ORDINALITY AS a(oid, ordinality)
         ), '') AS signature
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname || '.' || p.proname = ANY($1::text[])
`

/**
 * Every operator with an EQL operand — in ANY schema, for the reason the
 * parser comment gives: unqualified `CREATE OPERATOR` follows the
 * install-time search_path, so a "$user" schema legitimately holds them.
 * Operand types via `format_type` under the pinned empty search_path, so the
 * spelling matches the parser's (`integer`, `text[]`, `public.eql_v3_bigint`).
 * Extra operators (a user's own) are harmless — the differ only looks for
 * absences.
 */
const OPERATORS_SQL = `
  SELECT o.oprname AS name,
         CASE WHEN o.oprleft = 0 THEN 'none'
              ELSE pg_catalog.format_type(o.oprleft, NULL) END AS leftarg,
         CASE WHEN o.oprright = 0 THEN 'none'
              ELSE pg_catalog.format_type(o.oprright, NULL) END AS rightarg
  FROM pg_catalog.pg_operator o
  LEFT JOIN pg_catalog.pg_type lt ON lt.oid = o.oprleft
  LEFT JOIN pg_catalog.pg_namespace ln ON ln.oid = lt.typnamespace
  LEFT JOIN pg_catalog.pg_type rt ON rt.oid = o.oprright
  LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = rt.typnamespace
  WHERE ln.nspname IN ('${EQL_V3_SCHEMA_NAME}', '${EQL_V3_INTERNAL_SCHEMA_NAME}')
     OR rn.nspname IN ('${EQL_V3_SCHEMA_NAME}', '${EQL_V3_INTERNAL_SCHEMA_NAME}')
     OR lt.typname LIKE 'eql\\_v3\\_%'
     OR rt.typname LIKE 'eql\\_v3\\_%'
`

/**
 * Every cast with an EQL endpoint — OR-matched on either side, exactly as
 * {@link OPERATORS_SQL} matches operands. An AND over both endpoints would be
 * unreadable for a cast to or from a `pg_catalog` type (`jsonb`, `text`):
 * {@link parseExpectedSurface} takes every `CREATE CAST` in the bundle, so
 * such a cast would enter the expected set and never be found installed —
 * phantom "Cast missing" damage on every database, forever. The EQL half is
 * matched by schema and by the `eql_v3_` typname prefix, since the public
 * domains live in whatever schema the install-time search_path put them in.
 * Extra casts (a user's own) are harmless — the differ only looks for
 * absences.
 */
const CASTS_SQL = `
  SELECT pg_catalog.format_type(c.castsource, NULL) AS source,
         pg_catalog.format_type(c.casttarget, NULL) AS target
  FROM pg_catalog.pg_cast c
  JOIN pg_catalog.pg_type st ON st.oid = c.castsource
  JOIN pg_catalog.pg_namespace sn ON sn.oid = st.typnamespace
  JOIN pg_catalog.pg_type tt ON tt.oid = c.casttarget
  JOIN pg_catalog.pg_namespace tn ON tn.oid = tt.typnamespace
  WHERE sn.nspname IN ('${EQL_V3_SCHEMA_NAME}', '${EQL_V3_INTERNAL_SCHEMA_NAME}')
     OR tn.nspname IN ('${EQL_V3_SCHEMA_NAME}', '${EQL_V3_INTERNAL_SCHEMA_NAME}')
     OR st.typname LIKE 'eql\\_v3\\_%'
     OR tt.typname LIKE 'eql\\_v3\\_%'
`

/**
 * The two halves of the bundle's conditional ORE story: the default btree
 * operator class over `ore_block_256` (mirrors `eql validate`'s probe — see
 * `ORE_AVAILABLE_SQL` there for why `to_regtype`, not a `::regtype` cast),
 * and how many of the EXPECTED ORE domains ($1) carry the
 * `eql_ore_unavailable` poison CHECK the bundle installs when the class could
 * not be created. Scoped to those domains rather than counting by constraint
 * name alone — constraint names are not globally unique, so a same-named
 * CHECK on an unrelated domain must not flip a healthy install to
 * incoherent (or mask a missing poison on a fallback install).
 */
const ORE_STATE_SQL = `
  SELECT
    ${ORE_OPCLASS_PRESENT_EXPR} AS ore_opclass_present,
    (
      SELECT count(*)::int
      FROM pg_catalog.pg_constraint c
      JOIN pg_catalog.pg_type t ON t.oid = c.contypid
      JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
      WHERE c.conname = 'eql_ore_unavailable'
        AND tn.nspname || '.' || t.typname = ANY($1::text[])
    ) AS poisoned_domains
`

/**
 * `eql_v3.version()`, or `null` when that function is genuinely absent.
 *
 * Only a real "undefined function" (42883) reads as "version missing" — the
 * differ reports that as damage, because the bundle always installs it.
 * Anything else — EXECUTE denied, statement_timeout — is a failure to READ the
 * version rather than evidence about the install; returning `null` for those
 * would produce a full phantom object diff against a healthy database, so they
 * are rethrown. Callers must have established that the `eql_v3` schema exists.
 */
async function readInstalledEqlVersion(
  client: pg.ClientBase,
): Promise<string | null> {
  try {
    const version = await client.query<{ version: string }>(
      `SELECT ${EQL_V3_SCHEMA_NAME}.version() AS version`,
    )
    return version.rows[0]?.version ?? null
  } catch (error) {
    const code =
      error !== null && typeof error === 'object' && 'code' in error
        ? (error as { code?: string }).code
        : undefined
    if (code === '42883') return null
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(
      `Could not read ${EQL_V3_SCHEMA_NAME}.version(): ${detail}`,
      {
        cause: error,
      },
    )
  }
}

/**
 * Read what the database actually has. Exported for the live suite, which is
 * the only thing that can prove the catalogue spellings meet the bundle's.
 */
export async function readInstalledSurface(
  client: pg.ClientBase,
  expected: ExpectedSurface,
): Promise<InstalledSurface> {
  // Sequential on purpose: a single pg.Client serialises concurrent query()
  // calls anyway (and deprecates them); these are six fast catalogue reads.
  //
  // The read-only transaction exists for `SET LOCAL search_path = ''`:
  // `format_type` qualifies a name exactly when the type is not visible on
  // the search_path, so pinning it empty makes every non-catalogue type come
  // out fully qualified (`public.eql_v3_bigint`,
  // `eql_v3_internal.ore_block_256_term[]`) while `pg_catalog` — always
  // implicitly searched — keeps its canonical unqualified spellings
  // (`integer`, `text[]`). That is precisely the spelling the bundle parser
  // produces; without the pin the output would vary with the connection's
  // search_path. SET LOCAL dies with the transaction, so the caller's
  // session is untouched (the version() probe below runs after COMMIT and
  // needs the default path restored — `eql_v3.version` is qualified, but its
  // body's search_path is its own SET clause either way).
  await client.query('BEGIN READ ONLY')
  await client.query(`SET LOCAL search_path = ''`)
  const schemas = await client.query<{
    eql_v3_present: boolean
    eql_v3_internal_present: boolean
    pgcrypto_installed: boolean
    pgcrypto_schema: string | null
  }>(SCHEMAS_SQL)
  const types = await client.query<{ name: string }>(TYPES_SQL, [
    [...expected.domains, ...expected.types],
  ])
  const functions = await client.query<{ name: string; signature: string }>(
    FUNCTION_SIGNATURES_SQL,
    [[...expected.functions.keys()]],
  )
  const operators = await client.query<{
    name: string
    leftarg: string
    rightarg: string
  }>(OPERATORS_SQL)
  const casts = await client.query<{ source: string; target: string }>(
    CASTS_SQL,
  )
  const ore = await client.query<{
    ore_opclass_present: boolean
    poisoned_domains: number
  }>(ORE_STATE_SQL, [expected.oreDomains])
  // Ends the SET LOCAL scope. On a mid-transaction error the caller's
  // client.end() discards the aborted transaction with the connection.
  await client.query('COMMIT')

  const eqlV3SchemaPresent = schemas.rows[0]?.eql_v3_present === true
  const installedVersion = eqlV3SchemaPresent
    ? await readInstalledEqlVersion(client)
    : null

  const functionSignatures = new Map<string, Set<string>>()
  for (const row of functions.rows) {
    const name = row.name.toLowerCase()
    const existing = functionSignatures.get(name) ?? new Set<string>()
    existing.add(row.signature.toLowerCase())
    functionSignatures.set(name, existing)
  }

  return {
    eqlV3SchemaPresent,
    eqlV3InternalSchemaPresent:
      schemas.rows[0]?.eql_v3_internal_present === true,
    pgcryptoInstalled: schemas.rows[0]?.pgcrypto_installed === true,
    pgcryptoSchema:
      typeof schemas.rows[0]?.pgcrypto_schema === 'string'
        ? schemas.rows[0].pgcrypto_schema
        : null,
    installedVersion,
    presentTypes: new Set(types.rows.map((row) => row.name.toLowerCase())),
    functionSignatures,
    presentOperators: new Set(
      operators.rows.map(
        (row) =>
          `${row.name.toLowerCase()} (${row.leftarg.toLowerCase()}, ${row.rightarg.toLowerCase()})`,
      ),
    ),
    presentCasts: new Set(
      casts.rows.map(
        (row) => `${row.source.toLowerCase()} AS ${row.target.toLowerCase()}`,
      ),
    ),
    oreOpclassPresent: ore.rows[0]?.ore_opclass_present === true,
    poisonedDomains: ore.rows[0]?.poisoned_domains ?? 0,
  }
}

// ---------------------------------------------------------------------------
// Diffing
// ---------------------------------------------------------------------------

/**
 * An attributor from any object identity (qualified name, operator key,
 * signature text) to the bare EQL domain it concerns, so the report can group
 * per-domain. Longest name wins (`eql_v3_double_ord_ope` before
 * `eql_v3_double_ord`), and a domain's query-operand twin
 * (`eql_v3.query_double_ord`) attributes to the same bare name.
 */
function domainAttributor(
  expected: ExpectedSurface,
): (text: string) => string | undefined {
  const bareNames = [
    ...new Set(
      expected.domains.map((domain) =>
        domain
          .replace(/^public\./, '')
          .replace(/^eql_v3\.query_/, 'eql_v3_')
          .replace(/^eql_v3\./, 'eql_v3_'),
      ),
    ),
  ].sort((a, b) => b.length - a.length)
  return (text) => {
    for (const bare of bareNames) {
      if (
        text.includes(bare) ||
        text.includes(`query_${bare.slice('eql_v3_'.length)}`)
      ) {
        return bare
      }
    }
    return undefined
  }
}

/** Compare the expected surface with what the database has. Pure. */
export function diffSurface(
  expected: ExpectedSurface,
  installed: InstalledSurface,
): VerifyReport {
  const findings: SurfaceFinding[] = []
  const domainMentioned = domainAttributor(expected)

  if (!installed.eqlV3SchemaPresent) {
    return {
      status: 'not-installed',
      bundleVersion: expected.eqlVersion,
      installedVersion: null,
      counts: null,
      ore: null,
      findings: [
        {
          severity: 'damage',
          kind: 'schema',
          message: `The \`${EQL_V3_SCHEMA_NAME}\` schema does not exist — EQL is not installed. Run \`stash eql install\`.`,
        },
      ],
      ok: false,
    }
  }

  if (
    installed.installedVersion !== null &&
    installed.installedVersion !== expected.eqlVersion
  ) {
    return {
      status: 'version-mismatch',
      bundleVersion: expected.eqlVersion,
      installedVersion: installed.installedVersion,
      counts: null,
      ore: null,
      findings: [
        {
          severity: 'warning',
          kind: 'version',
          // Both remedies run the same pinned-bundle DDL, but `eql upgrade`
          // requires a stash.config.ts — on a one-shot `--database-url`
          // database, `install --force` is the one that actually works.
          message: `EQL ${installed.installedVersion} is installed, but this CLI pins EQL ${expected.eqlVersion} — the object-level surface checks only know the pinned bundle, so they were skipped. Run \`stash eql upgrade\` (or \`stash eql install --force --database-url ...\` for a database without a stash.config.ts), then verify again.`,
        },
      ],
      // NOT ok: nothing was verified. `ok` must mean "checked and complete" —
      // an exit-0 here would let `stash eql verify || fail` pass on a damaged
      // older install, the command's headline scenario.
      ok: false,
    }
  }

  if (!installed.eqlV3InternalSchemaPresent) {
    findings.push({
      severity: 'damage',
      kind: 'schema',
      message: `The \`${EQL_V3_INTERNAL_SCHEMA_NAME}\` schema is missing.`,
    })
  }
  if (!installed.pgcryptoInstalled) {
    findings.push({
      severity: 'damage',
      kind: 'extension',
      message:
        'The pgcrypto extension is not installed — every EQL hashing function fails without it.',
    })
  } else if (
    installed.pgcryptoSchema !== null &&
    !SUPPORTED_PGCRYPTO_SCHEMAS.includes(installed.pgcryptoSchema)
  ) {
    // Same rule as the install preflight: the EQL functions' pinned
    // search_path only resolves pgcrypto from these schemas, so presence
    // alone is not enough — a relocated extension fails at runtime.
    findings.push({
      severity: 'damage',
      kind: 'extension',
      message: `pgcrypto is installed in schema "${installed.pgcryptoSchema}", which is not on the EQL search_path — every EQL hashing function fails at runtime. Fix with: ALTER EXTENSION pgcrypto SET SCHEMA extensions`,
    })
  }
  if (installed.installedVersion === null) {
    findings.push({
      severity: 'damage',
      kind: 'version',
      message: `\`${EQL_V3_SCHEMA_NAME}.version()\` is missing or failed — the bundle always installs it.`,
    })
  }

  for (const domain of expected.domains) {
    if (!installed.presentTypes.has(domain)) {
      findings.push({
        severity: 'damage',
        kind: 'domain',
        domain: domainMentioned(domain),
        message: `Domain \`${domain}\` is missing.`,
      })
    }
  }
  for (const type of expected.types) {
    if (!installed.presentTypes.has(type)) {
      findings.push({
        severity: 'damage',
        kind: 'type',
        message: `Type \`${type}\` is missing.`,
      })
    }
  }

  // Signature-level, not count-level: a stale or hand-created same-name
  // function must not mask a genuinely missing overload.
  let functionsPresent = 0
  for (const [name, expectedSignatures] of expected.functions) {
    const present = installed.functionSignatures.get(name) ?? new Set<string>()
    const missing = expectedSignatures.filter(
      (signature) => !present.has(signature),
    )
    functionsPresent += expectedSignatures.length - missing.length
    if (missing.length === expectedSignatures.length) {
      findings.push({
        severity: 'damage',
        kind: 'function',
        domain: domainMentioned(name),
        message: `Function \`${name}\` is missing (expected ${expectedSignatures.length} overload${expectedSignatures.length === 1 ? '' : 's'}).`,
      })
    } else {
      for (const signature of missing) {
        findings.push({
          severity: 'damage',
          kind: 'function',
          domain: domainMentioned(`${name}(${signature})`),
          message: `Function \`${name}(${signature})\` is missing.`,
        })
      }
    }
  }

  let operatorsPresent = 0
  for (const operator of expected.operators) {
    if (installed.presentOperators.has(operator)) {
      operatorsPresent += 1
    } else {
      findings.push({
        severity: 'damage',
        kind: 'operator',
        domain: domainMentioned(operator),
        message: `Operator \`${operator}\` is missing.`,
      })
    }
  }

  let castsPresent = 0
  for (const cast of expected.casts) {
    // The parser spells cast types as the bundle wrote them; the catalog read
    // spells them `schema.typname`. Both are qualified, so compare directly.
    if (installed.presentCasts.has(cast)) {
      castsPresent += 1
    } else {
      findings.push({
        severity: 'damage',
        kind: 'cast',
        message: `Cast \`${cast}\` is missing.`,
      })
    }
  }

  // The ORE conditional: exactly one of the two halves must be present, in
  // full. Anything else is a half-working state the bundle never produces.
  const expectedPoisoned = expected.oreDomains.length
  const oreState = classifyOreState({
    opclassPresent: installed.oreOpclassPresent,
    poisonedDomains: installed.poisonedDomains,
    expectedPoisoned,
  })
  const oreDescription = describeOreState(oreState)
  findings.push({
    severity: oreDescription.severity === 'damage' ? 'damage' : 'expected',
    kind: 'opclass',
    // The counts only mean anything in the two incoherent states, where they
    // say how far the half-application got.
    message:
      oreDescription.severity === 'damage'
        ? `${oreDescription.message} (${installed.poisonedDomains} of ${expectedPoisoned} ORE domains carry the poison CHECK.)`
        : oreDescription.message,
  })

  const damaged = findings.some((finding) => finding.severity === 'damage')
  return {
    status: damaged ? 'incomplete' : 'complete',
    bundleVersion: expected.eqlVersion,
    installedVersion: installed.installedVersion,
    counts: {
      domains: {
        expected: expected.domains.length,
        present: expected.domains.filter((domain) =>
          installed.presentTypes.has(domain),
        ).length,
      },
      types: {
        expected: expected.types.length,
        present: expected.types.filter((type) =>
          installed.presentTypes.has(type),
        ).length,
      },
      functions: {
        expected: [...expected.functions.values()].reduce(
          (sum, signatures) => sum + signatures.length,
          0,
        ),
        present: functionsPresent,
      },
      operators: {
        expected: expected.operators.length,
        present: operatorsPresent,
      },
      casts: { expected: expected.casts.length, present: castsPresent },
    },
    ore: {
      opclassPresent: installed.oreOpclassPresent,
      poisonedDomains: installed.poisonedDomains,
      expectedPoisoned,
      state: oreState,
    },
    findings,
    ok: !damaged,
  }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/** Connect, read, and diff — the whole check, in a handful of catalog reads. */
export async function verifyEqlSurface(
  databaseUrl: string,
): Promise<VerifyReport> {
  const expected = bundledExpectedSurface()
  const client = createPgClient(databaseUrl)
  try {
    await client.connect()
  } catch (error) {
    await client.end().catch(() => {})
    if (error instanceof TlsVerificationError) throw error
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`Failed to connect to database: ${detail}`, {
      cause: error,
    })
  }
  try {
    const installed = await readInstalledSurface(client, expected)
    return diffSurface(expected, installed)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`EQL surface verification failed: ${detail}`, {
      cause: error,
    })
  } finally {
    await client.end()
  }
}

/**
 * The ORE half of an install as {@link readOreState} could read it.
 *
 * `comparable: false` means the installed EQL is not the pinned one, so there
 * is no honest ORE answer to give — not that anything is wrong. Callers must
 * render it as "could not compare", never as damage.
 */
export type OreStateReading =
  | {
      comparable: true
      opclassPresent: boolean
      poisonedDomains: number
      expectedPoisoned: number
      state: OreSurfaceState
    }
  | {
      comparable: false
      bundleVersion: string
      installedVersion: string | null
    }

/**
 * Read just the ORE half of an install — the two catalogue values and the
 * state they classify to (#891).
 *
 * `eql status` wants the ORE answer and nothing else. Routing it through
 * {@link verifyEqlSurface} would work but would read the whole 3,000-operator
 * surface to render one row.
 *
 * It still needs {@link diffSurface}'s version gate, though, because the ORE
 * state is NOT a pure catalogue fact: `expectedPoisoned` is the pinned
 * bundle's ORE-domain count, and {@link ORE_STATE_SQL} counts poisoned domains
 * only among that same pinned list. So a healthy fallback install of a
 * DIFFERENT EQL — the ordinary "CLI upgraded, database not yet" case — poisons
 * ITS domains, of which the pinned list sees only some, and
 * {@link classifyOreState} reads the shortfall as `incoherent-unpoisoned`
 * damage. Reporting a version skew as `comparable: false` is what stops
 * `eql status` telling that operator to reinstall `--force` over nothing.
 */
export async function readOreState(
  client: pg.ClientBase,
): Promise<OreStateReading> {
  const expected = bundledExpectedSurface()
  const installedVersion = await readInstalledEqlVersion(client)
  if (installedVersion !== expected.eqlVersion) {
    return {
      comparable: false,
      bundleVersion: expected.eqlVersion,
      installedVersion,
    }
  }
  const result = await client.query<{
    ore_opclass_present: boolean
    poisoned_domains: number
  }>(ORE_STATE_SQL, [expected.oreDomains])
  const observed = {
    opclassPresent: result.rows[0]?.ore_opclass_present === true,
    poisonedDomains: result.rows[0]?.poisoned_domains ?? 0,
    expectedPoisoned: expected.oreDomains.length,
  }
  return { comparable: true, ...observed, state: classifyOreState(observed) }
}
