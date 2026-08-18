import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { ColumnSchema, EncryptConfig } from '@cipherstash/stack/schema'
import * as p from '@clack/prompts'
import { fetchPhysicalColumns } from '@/commands/encrypt/lib/db-readers.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadEncryptSchemas, loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'

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
  /**
   * `current_user` — the role the connection authenticated as. Carried for the
   * privilege finding, which is unactionable without naming the role to grant
   * to. Absent only if the read itself returned nothing.
   */
  connectedRole?: string
  /**
   * For each declared table, every schema OTHER than {@link searchedSchema} in
   * which a relation of that name lives.
   *
   * Populated per catalogue ROW, so a name present in the searched schema AND
   * elsewhere lands here AND in {@link searchedSchemaRelations} — this is NOT
   * scoped to tables missing from {@link searchedSchema}, and must not be
   * "tidied" into that invariant: {@link ambiguousTableIssue} reads exactly
   * that overlap to report a shadowed table name, and narrowing this field
   * would delete that rule with every test still passing except its own.
   *
   * With {@link searchedSchemaRelations} it also separates "your `search_path`
   * points at the wrong schema" (recoverable, the table is right there) from
   * "the migration that creates this table has not run" (a real failure). Empty
   * for a table that exists in no other schema.
   */
  elsewhere: Map<string, string[]>
  /**
   * Declared tables that `pg_catalog` reports IN {@link searchedSchema} — the
   * third state, and the reason this field exists.
   *
   * {@link columns} comes from `information_schema`, which PostgreSQL filters
   * to objects the connected role holds a privilege on; this comes from
   * `pg_class`, which it does not filter. A table in here but absent from
   * `columns` therefore exists, right where the declaration says, and the role
   * simply cannot see it. Without the distinction that table appears in neither
   * map and gets "does not exist in any schema of this database" — a false
   * statement that sends someone to re-run a migration that already ran.
   */
  searchedSchemaRelations: Set<string>
  /**
   * `table → column → domain_name` (null for a plain, non-domain type).
   *
   * Privilege-filtered, per above: absence means "not visible to this role",
   * which is only the same as "not there" once
   * {@link searchedSchemaRelations} has been consulted.
   */
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

  // Reported per TABLE, ahead of the column loop, for the same reason the
  // not-installed finding is reported once: one fact explains every column on
  // the table, and repeating it per column buries it under itself. The columns
  // still run their schema rules below; only their database rules are skipped.
  const unreachable = new Set<string>()
  if (dbState !== undefined) {
    for (const table of new Set(columns.map((column) => column.table))) {
      if (!dbState.columns.has(table)) {
        unreachable.add(table)
        issues.push(unreachableTableIssue(table, dbState))
        continue
      }

      // Reachable — but possibly not the only relation of that name. Reported
      // here, in the same per-table pass, so it precedes the column findings it
      // qualifies rather than trailing them.
      const ambiguous = ambiguousTableIssue(table, dbState)
      if (ambiguous !== undefined) issues.push(ambiguous)
    }
  }

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

    // Already reported once, above, against the table rather than this column.
    if (unreachable.has(column.table)) continue

    const observedColumns = dbState.columns.get(column.table)
    if (observedColumns === undefined) continue

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

/**
 * Why a declared table produced no columns from the database, in the order the
 * evidence settles it.
 *
 * Four situations reach here and only ONE of them is a failure of the
 * project's migrations. Reporting the others as "the migration has not been
 * applied" is not a hedge but a false statement — it sends someone to re-run a
 * migration that already ran, on a database where the table is right there.
 */
function unreachableTableIssue(
  table: string,
  observed: ObservedState,
): ValidationIssue {
  // A `schema.table` name arrives as that literal string, and both catalogue
  // reads compare it whole against a bare `relname` / `table_name` — so it
  // matches nothing anywhere and was reported as an unapplied migration.
  // `@cipherstash/migrate` does accept the spelling (`splitTableName` in
  // `packages/migrate/src/version.ts`, first dot wins), so the toolchain
  // disagrees with itself. Resolving it properly needs a schema-aware column
  // read, which is `fetchPhysicalColumns` — shared with `encrypt status` and
  // scoped to `current_schema()` by construction. Splitting the name here and
  // passing the bare half to that reader would be worse than the bug: on a
  // connection whose `search_path` is `public`, `app.users` would silently
  // validate against `public.users` and report another table's drift as this
  // one's. So: say what was not checked, and do not assert anything else.
  const dot = table.indexOf('.')
  if (dot >= 0) {
    return {
      table,
      severity: 'warning',
      message: `Table "${table}" is declared with a schema qualifier, and validate cannot check schema-qualified table names — it inspects current_schema() only and matches table names unqualified, so nothing about this table was checked. This is not a report that the table is missing. Declare it unqualified and point the connection at its schema to check it (e.g. ?options=-csearch_path%3D${table.slice(0, dot)}).`,
    }
  }

  // `columns` is read from `information_schema`, which PostgreSQL filters to
  // objects the role holds a privilege on; `searchedSchemaRelations` is read
  // from `pg_class`, which it does not. A table in the second and not the first
  // exists exactly where the declaration says and is merely invisible.
  //
  // Checked ahead of `elsewhere` deliberately: the declaration means the table
  // in the searched schema, so pointing `search_path` at a same-named relation
  // in some other schema is the wrong instruction even when one exists.
  if (observed.searchedSchemaRelations.has(table)) {
    const role = observed.connectedRole
    return {
      table,
      severity: 'warning',
      message: `Table "${table}" exists in schema "${observed.searchedSchema}" but is not visible to the connected role${role ? ` "${role}"` : ''} — information_schema reports only what the role holds a privilege on, so nothing about this table could be checked. This is a missing grant, not a missing migration${role ? `: GRANT SELECT ON ${quoteIdent(table)} TO ${quoteIdent(role)};` : '.'}`,
    }
  }

  const others = observed.elsewhere.get(table) ?? []
  if (others.length > 0) {
    return {
      table,
      severity: 'warning',
      message: `Table "${table}" exists in schema ${others.map((schema) => `"${schema}"`).join(' / ')}, not in "${observed.searchedSchema}" — validate only inspects current_schema() (the head of search_path), so nothing about this table could be checked. Point the connection at that schema to check it (e.g. ?options=-csearch_path%3D${others[0]}).`,
    }
  }

  return {
    table,
    severity: 'error',
    message: `Table "${table}" is declared in your encryption schema but does not exist in any schema of this database. The migration that creates it has not been applied.`,
  }
}

/**
 * A declared table name that resolved here AND exists in another schema.
 *
 * The complement of {@link unreachableTableIssue}: that one explains why
 * nothing was checked, this one qualifies what WAS. A bare name resolves
 * through `search_path`, so when two schemas carry it the declaration does not
 * pin which relation the application reads — and every finding around this one
 * describes whichever `current_schema()` happened to resolve to. Saying which
 * costs one line and is the difference between a report the reader can trust
 * and one they have to go and verify by hand.
 *
 * Info, deliberately, on all three counts that matter: it does not move the
 * exit code, so a healthy project stays green; `auth.users` exists in every
 * Supabase project, so a warning here would report the entire platform as
 * unclean; and warning is reserved for "nothing was checked", which is the
 * opposite of this case.
 *
 * `undefined` when the name is unambiguous — the overwhelmingly common case.
 */
function ambiguousTableIssue(
  table: string,
  observed: ObservedState,
): ValidationIssue | undefined {
  const others = observed.elsewhere.get(table) ?? []
  if (others.length === 0) return undefined

  return {
    table,
    severity: 'info',
    message: `Table "${table}" was checked as ${quoteIdent(observed.searchedSchema)}.${quoteIdent(table)}, the relation current_schema() resolves it to — but a relation of the same name also exists in schema ${others.map((schema) => `"${schema}"`).join(' / ')}. A bare table name resolves through search_path, so the declaration does not pin which one your application reads, and everything else validate reports for this table describes the "${observed.searchedSchema}" one. If the encrypted columns live in the other, point the connection at that schema to check it instead (e.g. ?options=-csearch_path%3D${others[0]}).`,
  }
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

/**
 * The schema both catalogue reads are scoped to, and the role they run as.
 * Reported in the not-found findings — which schema was searched, and (for the
 * privilege case) which role could not see what is in it.
 */
const SEARCHED_SCHEMA_SQL = `
  SELECT current_schema() AS searched_schema,
         current_user AS connected_role`

/**
 * Every schema a declared table name lives in, INCLUDING `current_schema()`.
 *
 * Deliberately unscoped, and deliberately not excluding the searched schema
 * either. This is the query that tells three situations apart, and it needs
 * both halves to do it: a name found only in another schema is a misconfigured
 * `search_path`, a name found in the searched schema but absent from the
 * privilege-filtered `information_schema` read is a missing grant, and a name
 * found nowhere is an unapplied migration. `pg_class` is not privilege
 * filtered, which is precisely why the second case is visible here and nowhere
 * else.
 *
 * The searched/elsewhere split is computed in SQL rather than by comparing
 * `nspname` against the other read's `searched_schema` in JS: that read falls
 * back to `'public'` when `current_schema()` is NULL, and a fallback compared
 * against real catalogue rows would classify a genuine `public` relation as
 * visible on a connection whose `search_path` resolves to nothing.
 *
 * `relkind IN ('r','p','v','m','f')` covers ordinary, partitioned, view,
 * materialized-view and foreign relations: any of them can carry the encrypted
 * columns, and a partitioned table in particular is an ordinary choice for the
 * large tables this command is pointed at.
 *
 * The system schemas are excluded because the scan is otherwise database-wide
 * and `information_schema` publishes views named `columns`, `domains`,
 * `parameters`, `routines`, `sequences`, `tables` and `triggers` — all ordinary
 * application table names. A project declaring one of them that had NOT run its
 * migration matched the system view, so instead of the error that says the
 * migration never ran it got a warning telling it to point `search_path` at
 * `information_schema` — and, being a warning, exit 0.
 *
 * The regex operators, not `NOT LIKE 'pg\_%'`: this SQL is a JS template
 * literal, which collapses `\_` to a bare `_`. That leaves a LIKE
 * single-character wildcard, which also matches `pgbouncer`, `pgsodium` and
 * every other real `pg`-prefixed schema — hiding relations that genuinely
 * answer the question. `!~ '^pg_'` needs no escaping to mean what it says.
 */
const TABLE_SCHEMAS_SQL = `
  SELECT c.relname AS table_name,
         n.nspname AS relation_schema,
         n.nspname = current_schema() AS is_searched_schema
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relname = ANY($1::text[])
    AND c.relkind = ANY(ARRAY['r','p','v','m','f'])
    AND n.nspname !~ '^pg_'
    AND n.nspname <> 'information_schema'
  ORDER BY n.nspname`

/** Read everything the database rules need, in six catalogue queries. */
export async function readObservedState(
  client: pg.ClientBase,
  tables: ReadonlyArray<string>,
): Promise<ObservedState> {
  const [installed, ore, schema, relations, columns, indexes] =
    await Promise.all([
      client.query<{ eql_installed: boolean }>(EQL_INSTALLED_SQL),
      client.query<{ ore_available: boolean }>(ORE_AVAILABLE_SQL),
      client.query<{ searched_schema: string; connected_role: string }>(
        SEARCHED_SCHEMA_SQL,
      ),
      client.query<{
        table_name: string
        relation_schema: string
        is_searched_schema: boolean | null
      }>(TABLE_SCHEMAS_SQL, [tables]),
      fetchPhysicalColumns(client, tables),
      client.query<{ table_name: string; indexdef: string }>(INDEX_DEFS_SQL, [
        tables,
      ]),
    ])

  const elsewhere = new Map<string, string[]>()
  const searchedSchemaRelations = new Set<string>()
  for (const row of relations.rows) {
    if (row.is_searched_schema === true) {
      searchedSchemaRelations.add(row.table_name)
      continue
    }
    elsewhere.set(row.table_name, [
      ...(elsewhere.get(row.table_name) ?? []),
      row.relation_schema,
    ])
  }

  return {
    eqlInstalled: installed.rows[0]?.eql_installed === true,
    oreAvailable: ore.rows[0]?.ore_available === true,
    searchedSchema: schema.rows[0]?.searched_schema ?? 'public',
    connectedRole: schema.rows[0]?.connected_role,
    elsewhere,
    searchedSchemaRelations,
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
  const client = createPgClient(databaseUrl)

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
