import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import type pg from 'pg'
import { createPgClient, TlsVerificationError } from '@/db/client.js'
import { EQL_V3_INTERNAL_SCHEMA_NAME, EQL_V3_SCHEMA_NAME } from './grants.js'

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
   * Distinct overload count per qualified routine name (functions and
   * aggregates share `pg_proc`, so they share this map). Quoted names are
   * stored unquoted: `eql_v3_internal.-`, matching `pg_proc.proname`.
   */
  functions: Map<string, number>
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
 * How the ORE half of the install reads. Only the first two are healthy:
 * the bundle either created the operator class (superuser install) or
 * skipped it and poisoned every ORE domain so the gap fails loudly
 * (managed-Postgres install — a supported configuration, not damage).
 */
export type OreSurfaceState =
  | 'indexable'
  | 'fallback'
  | 'incoherent-unpoisoned'
  | 'incoherent-poisoned'

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
  /** True when no damage was found. */
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
 * Reduce one routine argument to its type: the bundle names every argument
 * (`a public.eql_v3_bigint`, `val jsonb`) and uses no DEFAULTs or arg modes,
 * so dropping the first token of a multi-token entry leaves the type —
 * including multi-word types, which keep their remaining tokens. A
 * single-token entry (aggregate signatures are types-only) is already a type.
 */
function argType(entry: string): string {
  const tokens = entry.trim().split(/\s+/)
  return (tokens.length > 1 ? tokens.slice(1) : tokens).join(' ').toLowerCase()
}

/** Parse the pinned install SQL into the surface it creates unconditionally. */
export function parseExpectedSurface(sql: string): ExpectedSurface {
  const stripped = stripDollarQuoted(sql)

  // Domains are created inside `IF NOT EXISTS ... CREATE DOMAIN` DO blocks,
  // so they are read from the RAW text (any indentation) and deduped. They
  // are unconditional in effect — the guard only makes reinstalls idempotent.
  const domains = new Set<string>()
  for (const match of sql.matchAll(/^\s*CREATE DOMAIN\s+([\w.]+)\s+AS/gim)) {
    domains.add(match[1].toLowerCase())
  }

  const types = new Set<string>()
  for (const match of stripped.matchAll(/^CREATE TYPE\s+([\w.]+)\s+AS/gim)) {
    types.add(match[1].toLowerCase())
  }

  // Functions and aggregates: count DISTINCT type-signatures per name (the
  // bundle re-CREATEs some signatures, which must not inflate the expectation)
  // and fold both into one map — they share pg_proc on the observed side.
  const signatures = new Map<string, Set<string>>()
  const routinePattern =
    /^CREATE (?:OR REPLACE )?(?:FUNCTION|AGGREGATE)\s+((?:[\w]+\.)?(?:"[^"]+"|[\w]+))\s*\(([^)]*)\)/gim
  for (const match of stripped.matchAll(routinePattern)) {
    const name = unquoteName(match[1])
    const args = match[2].trim()
    const signature = args === '' ? '' : args.split(',').map(argType).join(', ')
    const existing = signatures.get(name) ?? new Set<string>()
    existing.add(signature)
    signatures.set(name, existing)
  }
  const functions = new Map<string, number>()
  for (const [name, sigs] of signatures) functions.set(name, sigs.size)

  // Operators: identity is (name, leftarg, rightarg). Names are created
  // unqualified (or explicitly `public.`) — either way they land in `public`,
  // so the schema is dropped from the key.
  const operators = new Set<string>()
  const operatorPattern = /^CREATE OPERATOR\s+([^\s(]+)\s*\(([\s\S]*?)\);/gim
  for (const match of stripped.matchAll(operatorPattern)) {
    const name = match[1].toLowerCase().replace(/^public\./, '')
    const left = /LEFTARG\s*=\s*([\w.[\]]+)/i.exec(match[2])?.[1] ?? 'none'
    const right = /RIGHTARG\s*=\s*([\w.[\]]+)/i.exec(match[2])?.[1] ?? 'none'
    operators.add(`${name} (${left.toLowerCase()}, ${right.toLowerCase()})`)
  }

  const casts = new Set<string>()
  for (const match of stripped.matchAll(
    /^CREATE CAST\s*\(\s*([\w.[\]]+)\s+AS\s+([\w.[\]]+)\s*\)/gim,
  )) {
    casts.add(`${match[1].toLowerCase()} AS ${match[2].toLowerCase()}`)
  }

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
  try {
    return parseExpectedSurface(readInstallSql())
  } catch (error) {
    throw new Error(
      'Failed to read the EQL v3 install SQL from `@cipherstash/eql`. Reinstall dependencies (the package ships the bundle in `dist/sql/`).',
      { cause: error },
    )
  }
}

// ---------------------------------------------------------------------------
// Reading the installed surface
// ---------------------------------------------------------------------------

export interface InstalledSurface {
  eqlV3SchemaPresent: boolean
  eqlV3InternalSchemaPresent: boolean
  pgcryptoInstalled: boolean
  installedVersion: string | null
  presentTypes: Set<string>
  functionCounts: Map<string, number>
  presentOperators: Set<string>
  presentCasts: Set<string>
  oreOpclassPresent: boolean
  poisonedDomains: number
}

const SCHEMAS_SQL = `
  SELECT
    EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = '${EQL_V3_SCHEMA_NAME}') AS eql_v3_present,
    EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS eql_v3_internal_present,
    EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pgcrypto') AS pgcrypto_installed
`

/** Domains and composite types by qualified name, in one probe. */
const TYPES_SQL = `
  SELECT n.nspname || '.' || t.typname AS name
  FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname || '.' || t.typname = ANY($1::text[])
`

const FUNCTION_COUNTS_SQL = `
  SELECT n.nspname || '.' || p.proname AS name, count(*)::int AS overloads
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname || '.' || p.proname = ANY($1::text[])
  GROUP BY 1
`

/**
 * Every operator with an EQL operand, in the same `<name> (<left>, <right>)`
 * spelling the bundle parser produces: catalog types via `format_type` (so
 * `integer`, `text[]`), everything else as `schema.typname`. Extra operators
 * (a user's own) are harmless — the differ only looks for absences.
 */
const OPERATORS_SQL = `
  SELECT o.oprname AS name,
         CASE WHEN o.oprleft = 0 THEN 'none'
              WHEN ln.nspname = 'pg_catalog' THEN pg_catalog.format_type(o.oprleft, NULL)
              ELSE ln.nspname || '.' || lt.typname END AS leftarg,
         CASE WHEN o.oprright = 0 THEN 'none'
              WHEN rn.nspname = 'pg_catalog' THEN pg_catalog.format_type(o.oprright, NULL)
              ELSE rn.nspname || '.' || rt.typname END AS rightarg
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

const CASTS_SQL = `
  SELECT sn.nspname || '.' || st.typname AS source,
         tn.nspname || '.' || tt.typname AS target
  FROM pg_catalog.pg_cast c
  JOIN pg_catalog.pg_type st ON st.oid = c.castsource
  JOIN pg_catalog.pg_namespace sn ON sn.oid = st.typnamespace
  JOIN pg_catalog.pg_type tt ON tt.oid = c.casttarget
  JOIN pg_catalog.pg_namespace tn ON tn.oid = tt.typnamespace
  WHERE sn.nspname IN ('public', '${EQL_V3_SCHEMA_NAME}', '${EQL_V3_INTERNAL_SCHEMA_NAME}')
    AND tn.nspname IN ('public', '${EQL_V3_SCHEMA_NAME}', '${EQL_V3_INTERNAL_SCHEMA_NAME}')
`

/**
 * The two halves of the bundle's conditional ORE story: the default btree
 * operator class over `ore_block_256` (mirrors `eql validate`'s probe — see
 * `ORE_AVAILABLE_SQL` there for why `to_regtype`, not a `::regtype` cast),
 * and how many domains carry the `eql_ore_unavailable` poison CHECK the
 * bundle installs when the class could not be created.
 */
const ORE_STATE_SQL = `
  SELECT
    EXISTS (
      SELECT 1
      FROM pg_catalog.pg_opclass c
      JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
      WHERE am.amname = 'btree'
        AND c.opcdefault
        AND c.opcintype = to_regtype('${EQL_V3_INTERNAL_SCHEMA_NAME}.ore_block_256')
    ) AS ore_opclass_present,
    (
      SELECT count(*)::int
      FROM pg_catalog.pg_constraint
      WHERE conname = 'eql_ore_unavailable' AND contypid <> 0
    ) AS poisoned_domains
`

async function readInstalledSurface(
  client: pg.ClientBase,
  expected: ExpectedSurface,
): Promise<InstalledSurface> {
  // Sequential on purpose: a single pg.Client serialises concurrent query()
  // calls anyway (and deprecates them); these are six fast catalogue reads.
  const schemas = await client.query<{
    eql_v3_present: boolean
    eql_v3_internal_present: boolean
    pgcrypto_installed: boolean
  }>(SCHEMAS_SQL)
  const types = await client.query<{ name: string }>(TYPES_SQL, [
    [...expected.domains, ...expected.types],
  ])
  const functions = await client.query<{ name: string; overloads: number }>(
    FUNCTION_COUNTS_SQL,
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
  }>(ORE_STATE_SQL)

  const eqlV3SchemaPresent = schemas.rows[0]?.eql_v3_present === true
  let installedVersion: string | null = null
  if (eqlV3SchemaPresent) {
    try {
      const version = await client.query<{ version: string }>(
        `SELECT ${EQL_V3_SCHEMA_NAME}.version() AS version`,
      )
      installedVersion = version.rows[0]?.version ?? null
    } catch {
      // A missing version() on a present schema is itself reported by the
      // differ — the function is part of the expected surface.
    }
  }

  return {
    eqlV3SchemaPresent,
    eqlV3InternalSchemaPresent:
      schemas.rows[0]?.eql_v3_internal_present === true,
    pgcryptoInstalled: schemas.rows[0]?.pgcrypto_installed === true,
    installedVersion,
    presentTypes: new Set(types.rows.map((row) => row.name.toLowerCase())),
    functionCounts: new Map(
      functions.rows.map((row) => [row.name.toLowerCase(), row.overloads]),
    ),
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
          message: `EQL ${installed.installedVersion} is installed, but this CLI pins EQL ${expected.eqlVersion} — the object-level surface checks only know the pinned bundle, so they were skipped. Run \`stash eql upgrade\`, then verify again.`,
        },
      ],
      ok: true,
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

  let functionsPresent = 0
  for (const [name, expectedOverloads] of expected.functions) {
    const present = installed.functionCounts.get(name) ?? 0
    functionsPresent += Math.min(present, expectedOverloads)
    if (present === 0) {
      findings.push({
        severity: 'damage',
        kind: 'function',
        domain: domainMentioned(name),
        message: `Function \`${name}\` is missing (expected ${expectedOverloads} overload${expectedOverloads === 1 ? '' : 's'}).`,
      })
    } else if (present < expectedOverloads) {
      findings.push({
        severity: 'damage',
        kind: 'function',
        domain: domainMentioned(name),
        message: `Function \`${name}\` has ${present} of ${expectedOverloads} expected overloads.`,
      })
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
  let oreState: OreSurfaceState
  if (installed.oreOpclassPresent) {
    oreState =
      installed.poisonedDomains === 0 ? 'indexable' : 'incoherent-poisoned'
  } else {
    oreState =
      installed.poisonedDomains === expectedPoisoned
        ? 'fallback'
        : 'incoherent-unpoisoned'
  }
  switch (oreState) {
    case 'indexable':
      findings.push({
        severity: 'expected',
        kind: 'opclass',
        message:
          'ORE operator class present — ORE ordered indexes are available (superuser install).',
      })
      break
    case 'fallback':
      findings.push({
        severity: 'expected',
        kind: 'opclass',
        message:
          'ORE operator class absent, and every ORE domain carries the loud-failure fallback. This is the supported managed-Postgres configuration (creating the class requires superuser), not a failed install — use the `_ord_ope` ordering domains.',
      })
      break
    case 'incoherent-poisoned':
      findings.push({
        severity: 'damage',
        kind: 'opclass',
        message: `The ORE operator class exists, but ${installed.poisonedDomains} domain${installed.poisonedDomains === 1 ? ' still carries' : 's still carry'} the \`eql_ore_unavailable\` poison CHECK — writes to those domains fail although ORE works. Reinstall with \`stash eql install --force\`.`,
      })
      break
    case 'incoherent-unpoisoned':
      findings.push({
        severity: 'damage',
        kind: 'opclass',
        message: `The ORE operator class is absent, but only ${installed.poisonedDomains} of ${expectedPoisoned} ORE domains carry the loud-failure fallback — the rest would fail at index/ORDER BY time with opaque errors instead. Reinstall with \`stash eql install --force\`.`,
      })
      break
  }

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
          (sum, count) => sum + count,
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
