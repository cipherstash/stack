import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { ColumnSchema, EncryptConfig } from '@cipherstash/stack/schema'
import * as p from '@clack/prompts'
import pg from 'pg'
import { fetchPhysicalColumns } from '@/commands/encrypt/lib/db-readers.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadEncryptSchemas, loadStashConfig } from '@/config/index.js'

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

export type Severity = 'error' | 'warning' | 'info'

export interface ValidationIssue {
  severity: Severity
  /** Omitted for schema-wide findings (e.g. "EQL is not installed"). */
  table?: string
  /** Omitted for schema-wide findings. */
  column?: string
  message: string
}

/**
 * One declared encrypted column, flattened out of the schema tuple.
 *
 * `eqlType` is the load-bearing field and the reason this type exists rather
 * than the raw `EncryptConfig`: the concrete domain (`public.eql_v3_integer_ord`)
 * is what distinguishes an OPE ordering column from its ORE twin, and what a
 * live database reports back as `information_schema.columns.domain_name`. It is
 * `undefined` only on the degraded config-only path (see
 * {@link collectDeclaredColumnsFromConfig}).
 */
export interface DeclaredColumn {
  table: string
  /** The DB column name (`column.getName()`), not the JS property name. */
  column: string
  /** e.g. `'public.eql_v3_integer_ord'`. */
  eqlType?: string
  cast_as: ColumnSchema['cast_as']
  queryable: boolean
  indexes: ColumnSchema['indexes']
}

/**
 * What a live database says about the declared schema. Every field is supplied
 * by the caller, so the rules below are testable without a database — see
 * {@link readObservedState} for the queries that populate it.
 */
export interface ObservedState {
  /**
   * Whether the EQL v3 bundle is installed at all. When `false` nothing else
   * here is meaningful: an absent ORE opclass would otherwise be reported as
   * "ORE unavailable on this platform" when the real answer is "run
   * `stash eql install`".
   */
  eqlInstalled: boolean
  /**
   * Whether the default btree opclass over `eql_v3_internal.ore_block_256`
   * exists. `CREATE OPERATOR CLASS` requires superuser, so managed Postgres
   * (Supabase and most hosted providers) installs without it and the EQL
   * bundle poisons every `_ord_ore` domain with an always-raising CHECK.
   */
  oreAvailable: boolean
  /**
   * The schema both catalogue reads were scoped to — `current_schema()`, the
   * head of `search_path`. Carried so the not-found findings can say WHERE
   * they looked: a table absent from this schema may simply live in another
   * one, and validate has no way to tell that from a missing migration.
   */
  searchedSchema: string
  /** `table → column → domain_name` (null for a plain, non-domain type). */
  columns: Map<string, Map<string, string | null>>
  /**
   * `table.column → extractor names` found inside functional index
   * definitions, e.g. `users.email → Set{'eq_term', 'match_term'}`.
   */
  indexedExtractors: Map<string, Set<string>>
}

// ---------------------------------------------------------------------------
// Collecting the declared schema
// ---------------------------------------------------------------------------

/**
 * Flatten the tuple passed to `Encryption({ schemas })` into one row per
 * encrypted column, carrying the concrete domain of each.
 */
export function collectDeclaredColumns(
  schemas: readonly AnyV3Table[],
): DeclaredColumn[] {
  const out: DeclaredColumn[] = []

  for (const table of schemas) {
    for (const builder of Object.values(table.columnBuilders)) {
      const built = builder.build()
      out.push({
        table: table.tableName,
        // Key by the DB name, exactly as `EncryptedTable.build()` does — a
        // camelCase property mapping to a snake_case column must be reported
        // (and drift-checked) under the name the database knows.
        column: builder.getName(),
        eqlType: builder.getEqlType(),
        cast_as: built.cast_as,
        queryable: builder.isQueryable(),
        indexes: built.indexes,
      })
    }
  }

  return out
}

/**
 * The degraded collection path, for a project whose installed
 * `@cipherstash/stack` predates `getSchemas()`.
 *
 * `eqlType` is left `undefined` — it genuinely is not recoverable from the
 * encrypt config — and `queryable` is inferred from the emitted index block
 * instead of from the domain's capability flags. Every rule that needs a domain
 * skips these columns rather than guessing.
 */
export function collectDeclaredColumnsFromConfig(
  config: EncryptConfig,
): DeclaredColumn[] {
  const out: DeclaredColumn[] = []

  for (const [tableName, columns] of Object.entries(config.tables)) {
    for (const [columnName, column] of Object.entries(columns)) {
      out.push({
        table: tableName,
        column: columnName,
        eqlType: undefined,
        cast_as: column.cast_as,
        // `?? {}` on BOTH, deliberately. The zod schema makes `indexes`
        // non-optional, but that zod never runs here: this config came out of
        // the user's own client through jiti, so the static type is a
        // description of what it should be, not a guarantee. A column missing
        // the key must degrade to "no indexes", not throw partway down the
        // rule list on `column.indexes.match`.
        queryable: Object.keys(column.indexes ?? {}).length > 0,
        indexes: column.indexes ?? {},
      })
    }
  }

  return out
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

/**
 * Wrap an identifier as a quoted SQL name, doubling any embedded quote.
 *
 * The missing-index finding hands the user runnable SQL, so a name carrying a
 * `"` has to survive the paste — `identifiersIn` already un-doubles it on the
 * read side, and this is the write side of the same rule.
 */
export function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`
}

/** Strip the schema qualifier: `'public.eql_v3_integer_ord'` → `'eql_v3_integer_ord'`. */
export function bareDomainName(eqlType: string): string {
  const dot = eqlType.lastIndexOf('.')
  return dot === -1 ? eqlType : eqlType.slice(dot + 1)
}

/**
 * The EQL v3 term extractors a column's indexes imply. These are the functions
 * a functional index must be built over — `CREATE INDEX ON users
 * (eql_v3.eq_term(email))` — because EQL forbids an operator class on the
 * domain itself.
 *
 * `ste_vec` is deliberately absent: an encrypted-JSONB column is served by a
 * GIN index over the column, not by a scalar extractor, so it is excluded from
 * the missing-index finding rather than reported against a recipe that does not
 * apply to it.
 */
export function expectedExtractors(indexes: ColumnSchema['indexes']): string[] {
  const out: string[] = []
  if (indexes.unique) out.push('eq_term')
  if (indexes.ope) out.push('ord_term')
  if (indexes.ore) out.push('ord_term_ore')
  if (indexes.match) out.push('match_term')
  return out
}

/**
 * Validate the declared schema, optionally against what a live database
 * reports.
 *
 * Pure: every database fact arrives through `observed`, so the drift rules have
 * real coverage without a database. Order of findings is stable (schema-wide
 * first, then declaration order) so callers and tests can compare lists.
 */
export function validateSchemas(
  columns: DeclaredColumn[],
  observed?: ObservedState,
): ValidationIssue[] {
  const issues: ValidationIssue[] = []

  // Report a missing EQL install once, up front, and drop the per-column
  // database rules: every one of them would otherwise fire on every column and
  // bury the single fact that explains all of them.
  const eqlMissing = observed !== undefined && !observed.eqlInstalled
  if (eqlMissing) {
    issues.push({
      severity: 'error',
      message:
        'EQL v3 is not installed in this database — run `stash eql install`. Skipping the database checks (declared domains, drift, indexes); the schema checks below still ran.',
    })
  }

  const dbState = eqlMissing ? undefined : observed

  for (const column of columns) {
    const at = { table: column.table, column: column.column }
    const domain = column.eqlType

    // -- Static rules ------------------------------------------------------

    // An `_ord_ore` domain needs the ORE btree operator class, which
    // `CREATE OPERATOR CLASS` reserves to superusers. The `_ord` twin is OPE
    // and indexes everywhere, so this is a portability warning even before a
    // database has been consulted. With a database it is upgraded to an error
    // (below) once the opclass is confirmed absent.
    if (domain?.endsWith('_ord_ore') && dbState === undefined) {
      issues.push({
        ...at,
        severity: 'warning',
        message: `${bareDomainName(domain)} needs the ORE btree operator class, which only a superuser can create — managed Postgres (Supabase and most hosted providers) installs EQL without it, and every value written to this column then fails a CHECK. Use ${bareDomainName(domain).replace(/_ord_ore$/, '_ord')} unless you control the database role.`,
      })
    }

    // Successor to the v2 "no indexes" Info. Read from the domain's capability
    // flags rather than from the emitted index keys: v2 checked
    // `ore`/`unique`/`match`/`ste_vec` and never learned about `ope`, so every
    // EQL v3 `_ord` column — `types.IntegerOrd`, `types.TimestampOrd`, … — was
    // reported as unsearchable. That bug is why this command was rewritten.
    if (!column.queryable) {
      issues.push({
        ...at,
        severity: 'info',
        message:
          'Storage-only column: it encrypts and decrypts but carries no query terms, so it cannot be searched, ordered or matched server-side. Pick a term-carrying domain (`types.TextEq`, `types.IntegerOrd`, `types.TextSearch`, …) if you need to query it.',
      })
    }

    // Guards for a hand-authored encrypt config: no `types.*` factory can
    // build either of the next two. `types.Boolean` is storage-only by
    // construction, and `match` is emitted only by the text domains.
    if (column.cast_as === 'boolean' && column.queryable) {
      issues.push({
        ...at,
        severity: 'error',
        message:
          'A searchable boolean column leaks its plaintext: with two possible values, an equality or ordering term is a direct read of the value. EQL v3 offers `types.Boolean` (storage-only) only, by design.',
      })
    }

    if (column.indexes.match && column.cast_as !== 'string') {
      issues.push({
        ...at,
        severity: 'error',
        message: `Free-text match needs a text domain — this column casts to "${column.cast_as}". Use \`types.TextMatch\` or \`types.TextSearch\`.`,
      })
    }

    if (column.indexes.ste_vec && column.cast_as !== 'json') {
      issues.push({
        ...at,
        severity: 'error',
        message: `Encrypted-JSONB search needs \`types.Json\` (cast_as "json") — this column casts to "${column.cast_as}".`,
      })
    }

    // -- Database rules ----------------------------------------------------

    if (dbState === undefined) continue

    const observedColumns = dbState.columns.get(column.table)

    // NOT an error. Both catalogue reads are scoped to one schema, so "absent
    // from `current_schema()`" covers two very different situations: a
    // migration that was never applied, and a perfectly healthy project whose
    // tables live in another schema (Prisma `multiSchema`, a tenant schema, or
    // a `schema.table` name in `encryptedTable`, which the reader compares
    // whole against a bare `table_name` and never matches). Validate cannot
    // distinguish them, so it reports where it looked and leaves the exit code
    // alone rather than failing a healthy database's CI.
    if (observedColumns === undefined) {
      issues.push({
        ...at,
        severity: 'warning',
        message: `Table "${column.table}" was not found in schema "${dbState.searchedSchema}", so nothing about this column could be checked against the database. Validate only inspects current_schema() (the head of search_path) — if this table lives in another schema, point the connection at it (e.g. ?options=-csearch_path%3D<schema>); otherwise the migration that creates it has not been applied.`,
      })
      continue
    }

    if (!observedColumns.has(column.column)) {
      issues.push({
        ...at,
        severity: 'error',
        message: `Column "${column.column}" is declared in your encryption schema but does not exist on table "${column.table}". Add it in a migration with the ${domain ? `\`${domain}\`` : 'declared EQL'} type.`,
      })
      continue
    }

    const observedDomain = observedColumns.get(column.column) ?? null

    if (observedDomain === null) {
      issues.push({
        ...at,
        severity: 'error',
        message: `Column "${column.column}" is a plain (non-EQL) column in the database, but your schema declares it encrypted${domain ? ` as \`${domain}\`` : ''}. Encrypted payloads written to it are unconstrained and unqueryable.`,
      })
    } else if (domain && observedDomain !== bareDomainName(domain)) {
      issues.push({
        ...at,
        severity: 'error',
        message: `Declared \`${domain}\` but the database column is \`${observedDomain}\`. The domains carry different terms, so writes fail the column's CHECK or queries silently return nothing. Align the migration with the schema.`,
      })
    }

    // The static `_ord_ore` warning becomes an error once the opclass is
    // confirmed absent: on that database every write to this column raises.
    if (domain?.endsWith('_ord_ore') && !dbState.oreAvailable) {
      issues.push({
        ...at,
        severity: 'error',
        message: `\`${domain}\` is unusable in this database: the EQL installer could not create the ORE operator class (it requires superuser), so the domain carries an always-raising CHECK. Switch to \`${domain.replace(/_ord_ore$/, '_ord')}\`.`,
      })
    }

    const missing = expectedExtractors(column.indexes).filter(
      (extractor) =>
        !dbState.indexedExtractors
          .get(`${column.table}.${column.column}`)
          ?.has(extractor),
    )

    if (missing.length > 0) {
      issues.push({
        ...at,
        severity: 'info',
        message: `No functional index over ${missing.map((e) => `\`eql_v3.${e}\``).join(' / ')} — queries against this column sequential-scan the table. e.g. CREATE INDEX ON ${quoteIdent(column.table)} (eql_v3.${missing[0]}(${quoteIdent(column.column)}));`,
      })
    }
  }

  return issues
}

// ---------------------------------------------------------------------------
// Reading the database
// ---------------------------------------------------------------------------

/**
 * Matches the head of an extractor call. `ord_term_ore` is listed before
 * `ord_term` because alternation is left-biased and one is a prefix of the
 * other; `\b` alone would not separate them.
 *
 * A factory, not a shared constant: a `/g` regex carries `lastIndex`, and a
 * module-level one would make an otherwise-pure function depend on where the
 * previous call happened to stop.
 */
const extractorHead = () =>
  /eql_v3\.(ord_term_ore|ord_term|eq_term|match_term)\s*\(/gi

/**
 * Pull `table.column → extractor` pairs out of `pg_get_indexdef()` output.
 *
 * Pure and exported so the parse has coverage without a database. The SQL
 * feeding it is one catalogue read, but the shapes it has to survive are all in
 * the string: quoted identifiers, `::` casts, a table qualifier, several
 * extractors in one index, and nested parentheses inside the argument list.
 *
 * It errs towards over-matching — a stray identifier in the argument list is
 * recorded as indexed. The finding this feeds is an Info ("no functional index
 * over …"), so a false negative is a missed hint while a false positive would
 * be a wrong instruction to create an index that already exists.
 */
export function parseIndexedExtractors(
  defs: ReadonlyArray<{ table: string; indexdef: string }>,
): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()

  for (const { table, indexdef } of defs) {
    const pattern = extractorHead()
    let head = pattern.exec(indexdef)
    while (head !== null) {
      const extractor = head[1].toLowerCase()
      const args = balancedArgs(indexdef, head.index + head[0].length)
      for (const column of identifiersIn(args)) {
        const key = `${table}.${column}`
        const set = out.get(key) ?? new Set<string>()
        set.add(extractor)
        out.set(key, set)
      }
      head = pattern.exec(indexdef)
    }
  }

  return out
}

/**
 * The argument text of a call whose opening `(` has already been consumed:
 * everything up to the matching `)`. Parenthesis-balanced because a cast
 * renders as `eql_v3.ord_term((col)::public.eql_v3_text_ord)`, where a
 * first-`)`-wins scan would stop inside the arguments.
 */
function balancedArgs(source: string, start: number): string {
  let depth = 1
  for (let i = start; i < source.length; i++) {
    const ch = source[i]
    if (ch === '(') depth++
    else if (ch === ')') {
      depth--
      if (depth === 0) return source.slice(start, i)
    }
  }
  return source.slice(start)
}

/**
 * Identifiers inside an extractor's argument list, with `::` cast targets
 * removed and quoting unwrapped. `pg_get_indexdef` renders an expression index
 * as e.g. `eql_v3.eq_term(email)`, `eql_v3.eq_term("user email")`, or
 * `eql_v3.ord_term((users.col)::public.eql_v3_text_ord)`.
 */
function identifiersIn(args: string): string[] {
  const out: string[] = []
  // Quoted identifiers first — they may contain characters the bare-identifier
  // pattern would split on.
  const quoted = /"((?:[^"]|"")*)"/g
  for (const match of args.matchAll(quoted)) {
    out.push(match[1].replace(/""/g, '"'))
  }
  // Then bare identifiers, with quoted runs and cast targets blanked out so
  // neither contributes a spurious name.
  const rest = args
    .replace(quoted, ' ')
    .replace(/::\s*[A-Za-z_][\w.]*/g, ' ')
    // A schema/table qualifier: keep only the final component.
    .replace(/[A-Za-z_]\w*\s*\./g, ' ')
  for (const match of rest.matchAll(/[A-Za-z_]\w*/g)) {
    out.push(match[0])
  }
  return out
}

/**
 * Whether the ORE btree operator class exists. Mirrors the EQL bundle's own
 * fallback test (`ore_fallback.sql`), with one deliberate difference:
 * `to_regtype` returns NULL where the bundle's `::regtype` cast raises, so this
 * degrades to `false` on a database with no EQL installed instead of throwing.
 * That is why the not-installed case is detected and reported separately.
 */
const ORE_AVAILABLE_SQL = `
  SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_opclass c
    JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
    WHERE am.amname = 'btree'
      AND c.opcdefault
      AND c.opcintype = to_regtype('eql_v3_internal.ore_block_256')
  ) AS ore_available`

const EQL_INSTALLED_SQL = `
  SELECT EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'eql_v3'
  ) AS eql_installed`

/**
 * Constrained to the declared tables, not the whole schema. Unfiltered this
 * fetches and regex-parses every `pg_get_indexdef()` in the database to answer
 * a question about a handful of columns — on a large schema, thousands of
 * definitions for nothing.
 */
const INDEX_DEFS_SQL = `
  SELECT c.relname AS table_name,
         pg_catalog.pg_get_indexdef(i.indexrelid) AS indexdef
  FROM pg_catalog.pg_index i
  JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND c.relname = ANY($1::text[])`

/** The schema both catalogue reads are scoped to. Reported in not-found findings. */
const SEARCHED_SCHEMA_SQL = `SELECT current_schema() AS searched_schema`

/** Read everything the database rules need, in five catalogue queries. */
export async function readObservedState(
  client: pg.ClientBase,
  tables: ReadonlyArray<string>,
): Promise<ObservedState> {
  const [installed, ore, schema, columns, indexes] = await Promise.all([
    client.query<{ eql_installed: boolean }>(EQL_INSTALLED_SQL),
    client.query<{ ore_available: boolean }>(ORE_AVAILABLE_SQL),
    client.query<{ searched_schema: string }>(SEARCHED_SCHEMA_SQL),
    fetchPhysicalColumns(client, tables),
    client.query<{ table_name: string; indexdef: string }>(INDEX_DEFS_SQL, [
      tables,
    ]),
  ])

  return {
    eqlInstalled: installed.rows[0]?.eql_installed === true,
    oreAvailable: ore.rows[0]?.ore_available === true,
    searchedSchema: schema.rows[0]?.searched_schema ?? 'public',
    columns,
    indexedExtractors: parseIndexedExtractors(
      indexes.rows.map((row) => ({
        table: row.table_name,
        indexdef: row.indexdef,
      })),
    ),
  }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/**
 * Print validation issues using `@clack/prompts` log methods.
 *
 * @returns `true` if there are any errors (severity === 'error').
 */
export function reportIssues(issues: ValidationIssue[]): boolean {
  for (const issue of issues) {
    const line =
      issue.table && issue.column
        ? `${issue.table}.${issue.column}: ${issue.message}`
        : issue.message

    switch (issue.severity) {
      case 'error':
        p.log.error(line)
        break
      case 'warning':
        p.log.warn(line)
        break
      case 'info':
        p.log.info(line)
        break
    }
  }

  const errors = issues.filter((i) => i.severity === 'error').length
  const warnings = issues.filter((i) => i.severity === 'warning').length
  const infos = issues.filter((i) => i.severity === 'info').length

  if (errors > 0) {
    p.outro(
      `${errors} error${errors !== 1 ? 's' : ''}, ${warnings} warning${warnings !== 1 ? 's' : ''}.`,
    )
  } else if (warnings > 0) {
    p.outro(`No errors found. ${warnings} warning${warnings !== 1 ? 's' : ''}.`)
  } else if (infos > 0) {
    p.outro(`No errors or warnings. ${infos} info${infos !== 1 ? 's' : ''}.`)
  } else {
    p.outro('No issues found.')
  }

  return errors > 0
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

export async function validateCommand(options: {
  supabase?: boolean
  databaseUrl?: string
}) {
  p.intro(runnerCommand(detectPackageManager(), 'stash eql validate'))

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })
  s.stop('Configuration loaded.')

  s.start(`Loading encrypt client from ${config.client}...`)
  const { config: encryptConfig, schemas } = await loadEncryptSchemas(
    config.client,
  )
  s.stop('Encrypt client loaded.')

  const columns = schemas
    ? collectDeclaredColumns(schemas)
    : collectDeclaredColumnsFromConfig(encryptConfig)

  if (!schemas) {
    p.log.warn(
      'Your installed @cipherstash/stack does not expose `getSchemas()`, so the concrete EQL domain of each column is unavailable. Domain checks (ORE portability, database drift) were skipped — upgrade @cipherstash/stack to run them.',
    )
  }

  const tableCount = new Set(columns.map((column) => column.table)).size
  p.log.success(
    `Schema loaded: ${tableCount} table${tableCount !== 1 ? 's' : ''}, ${columns.length} encrypted column${columns.length !== 1 ? 's' : ''}`,
  )

  const observed = await tryReadObservedState(config.databaseUrl, columns)

  const issues = validateSchemas(columns, observed)

  if (issues.length === 0) {
    p.outro('No issues found.')
    return
  }

  console.log() // blank line before issues
  const hasErrors = reportIssues(issues)

  if (hasErrors) {
    process.exit(1)
  }
}

/**
 * Connect and read the observed state, or return `undefined` and say why.
 *
 * A database that cannot be reached is not a validation failure: the schema
 * rules are worth running on a laptop with no database up, and failing here
 * would make the command unusable in exactly that setting.
 */
async function tryReadObservedState(
  databaseUrl: string | undefined,
  columns: DeclaredColumn[],
): Promise<ObservedState | undefined> {
  if (!databaseUrl) {
    p.log.info(
      'No database URL resolved — skipping the database checks (drift, ORE availability, functional indexes). Pass --database-url or set DATABASE_URL to run them.',
    )
    return undefined
  }

  const tables = [...new Set(columns.map((column) => column.table))]
  const client = new pg.Client({ connectionString: databaseUrl })

  try {
    await client.connect()
    return await readObservedState(client, tables)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    p.log.info(
      `Could not read the database (${message}) — skipping the database checks (drift, ORE availability, functional indexes). The schema checks below still ran.`,
    )
    return undefined
  } finally {
    await client.end().catch(() => {})
  }
}
