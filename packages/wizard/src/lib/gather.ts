/**
 * Pre-agent context gathering.
 *
 * Collects all the information the agent needs BEFORE it runs,
 * so the agent can do a single-shot file write with no discovery.
 * This eliminates the majority of API round trips.
 */

import {
  existsSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
} from 'node:fs'
import { closeSync } from 'node:fs'
import { join, resolve } from 'node:path'
import * as p from '@clack/prompts'
import { introspectDatabase } from '../tools/wizard-tools.js'
import { checkEnvKeys } from '../tools/wizard-tools.js'
import type {
  DetectedPackageManager,
  Integration,
  WizardMode,
} from './types.js'

export type { WizardMode } from './types.js'

export interface ColumnSelection {
  tableName: string
  columnName: string
  dataType: string
  udtName: string
}

export interface GatheredContext {
  /** The integration type. */
  integration: Integration
  /** Tables and columns the user selected for encryption. Empty in plan
   *  mode — the planning agent proposes scope. */
  selectedColumns: ColumnSelection[]
  /** Drizzle schema file paths and their contents (drizzle only). */
  schemaFiles: Array<{ path: string; content: string }>
  /** Where to write the encryption client file. */
  outputPath: string
  /** Package manager install command. */
  installCommand: string
  /** Whether stash.config.ts already exists. */
  hasStashConfig: boolean
}

export interface GatherContextOptions {
  cwd: string
  integration: Integration
  packageManager: DetectedPackageManager | undefined
  mode?: WizardMode
}

/**
 * Gather all context needed for the agent via CLI prompts and local I/O.
 * No AI calls are made here — this is pure CLI interaction.
 *
 * Plan mode skips the column-selection TUI because the planning agent's
 * job is to *propose* scope, not act on a pre-committed list. Schema
 * files are still collected so the agent has something to ground its
 * proposals in.
 */
export async function gatherContext(
  options: GatherContextOptions,
): Promise<GatheredContext> {
  const { cwd, integration, packageManager } = options
  const mode: WizardMode = options.mode ?? 'implement'

  const installCmd = packageManager
    ? `${packageManager.installCommand} @cipherstash/stack`
    : 'npm install @cipherstash/stack'

  const hasStashConfig =
    existsSync(resolve(cwd, 'stash.config.ts')) ||
    existsSync(resolve(cwd, 'stash.config.js'))

  let selectedColumns: ColumnSelection[]
  if (mode === 'plan') {
    selectedColumns = []
  } else {
    const tables = await tryIntrospect(cwd)
    if (tables && tables.length > 0) {
      selectedColumns = await selectColumnsFromDb(tables)
    } else {
      selectedColumns = await selectColumnsManually()
    }

    if (selectedColumns.length === 0) {
      p.log.warn('No columns selected for encryption.')
      p.cancel('Nothing to do.')
      process.exit(0)
    }
  }

  // Schema files are collected in both modes — the planning agent grounds
  // its proposals in real schema content; the implementation agent edits
  // it directly.
  let schemaFiles: Array<{ path: string; content: string }> = []
  if (integration === 'drizzle') {
    schemaFiles = findDrizzleSchemaFiles(cwd)
  }

  // Determine output path
  const hasSrcDir = existsSync(resolve(cwd, 'src'))
  const outputPath = hasSrcDir
    ? 'src/encryption/index.ts'
    : 'encryption/index.ts'

  return {
    integration,
    selectedColumns,
    schemaFiles,
    outputPath,
    installCommand: installCmd,
    hasStashConfig,
  }
}

// --- DB introspection ---

interface DbTable {
  tableName: string
  columns: Array<{
    columnName: string
    dataType: string
    udtName: string
    isEqlEncrypted: boolean
  }>
}

async function tryIntrospect(cwd: string): Promise<DbTable[] | null> {
  // Check for DATABASE_URL in common env files
  const envFiles = ['.env', '.env.local', '.env.development']
  let dbUrl: string | undefined

  for (const envFile of envFiles) {
    const envPath = resolve(cwd, envFile)
    if (!existsSync(envPath)) continue

    const content = readFileSync(envPath, 'utf-8')
    const match = content.match(/^DATABASE_URL\s*=\s*["']?(.+?)["']?\s*$/m)
    if (match) {
      dbUrl = match[1]
      break
    }
  }

  if (!dbUrl) {
    // Ask user for DATABASE_URL
    const urlInput = await p.text({
      message:
        'Enter your DATABASE_URL (or press Enter to skip and enter tables manually):',
      placeholder: 'postgresql://user:pass@host:5432/dbname',
    })

    if (p.isCancel(urlInput) || !urlInput?.trim()) {
      return null
    }
    dbUrl = urlInput.trim()
  }

  const s = p.spinner()
  s.start('Introspecting database...')
  try {
    const tables = await introspectDatabase(dbUrl)
    s.stop(`Found ${tables.length} table${tables.length !== 1 ? 's' : ''}`)
    return tables
  } catch (err) {
    s.stop('Could not connect to database')
    p.log.warn(
      `Connection failed: ${err instanceof Error ? err.message : 'unknown error'}`,
    )
    return null
  }
}

// --- Column selection from DB introspection ---

async function selectColumnsFromDb(
  tables: DbTable[],
): Promise<ColumnSelection[]> {
  // Show tables and let user pick which ones
  const tableChoices = tables.map((t) => ({
    value: t.tableName,
    label: t.tableName,
    hint: `${t.columns.length} columns${t.columns.some((c) => c.isEqlEncrypted) ? ', some already encrypted' : ''}`,
  }))

  const selectedTables = await p.multiselect({
    message: 'Which tables do you want to add encryption to?',
    options: tableChoices,
    required: true,
  })

  if (p.isCancel(selectedTables)) {
    p.cancel('Cancelled.')
    process.exit(0)
  }

  // For each selected table, let user pick columns
  const allSelected: ColumnSelection[] = []

  for (const tableName of selectedTables) {
    const table = tables.find((t) => t.tableName === tableName)!
    const encryptableColumns = table.columns.filter(
      (c) =>
        !c.isEqlEncrypted &&
        c.columnName !== 'id' &&
        !c.columnName.endsWith('_id') &&
        c.columnName !== 'created_at' &&
        c.columnName !== 'updated_at',
    )

    if (encryptableColumns.length === 0) {
      p.log.info(
        `No encryptable columns found in ${tableName} (IDs, timestamps, and already-encrypted columns are excluded).`,
      )
      continue
    }

    const columnChoices = encryptableColumns.map((c) => ({
      value: c.columnName,
      label: `${c.columnName} (${c.udtName})`,
    }))

    const selectedCols = await p.multiselect({
      message: `Which columns in "${tableName}" should be encrypted?`,
      options: columnChoices,
      required: false,
    })

    if (p.isCancel(selectedCols)) {
      p.cancel('Cancelled.')
      process.exit(0)
    }

    for (const colName of selectedCols) {
      const col = table.columns.find((c) => c.columnName === colName)!
      allSelected.push({
        tableName,
        columnName: colName,
        dataType: col.dataType,
        udtName: col.udtName,
      })
    }
  }

  return allSelected
}

// --- Manual column entry ---

async function selectColumnsManually(): Promise<ColumnSelection[]> {
  p.log.info('Enter your table and column names manually.')

  const columns: ColumnSelection[] = []

  let addMore = true
  while (addMore) {
    const tableName = await p.text({
      message: 'Table name:',
      placeholder: 'e.g. users',
    })

    if (p.isCancel(tableName) || !tableName?.trim()) break

    const columnNames = await p.text({
      message: `Column names to encrypt in "${tableName}" (comma-separated):`,
      placeholder: 'e.g. email, name, phone',
    })

    if (p.isCancel(columnNames) || !columnNames?.trim()) break

    for (const col of columnNames
      .split(',')
      .map((c) => c.trim())
      .filter(Boolean)) {
      const dataType = await p.select({
        message: `Data type for "${tableName}.${col}":`,
        options: [
          {
            value: 'text',
            label: 'Text / String',
            hint: 'varchar, text, char, uuid',
          },
          { value: 'number', label: 'Number', hint: 'integer, float, numeric' },
          { value: 'boolean', label: 'Boolean' },
          { value: 'date', label: 'Date / Timestamp' },
          { value: 'json', label: 'JSON / JSONB' },
        ],
      })

      if (p.isCancel(dataType)) break

      columns.push({
        tableName: tableName.trim(),
        columnName: col,
        dataType: dataType,
        udtName: dataType,
      })
    }

    const more = await p.confirm({
      message: 'Add another table?',
      initialValue: false,
    })

    if (p.isCancel(more)) break
    addMore = more
  }

  return columns
}

// --- Drizzle schema discovery ---

function findDrizzleSchemaFiles(
  cwd: string,
): Array<{ path: string; content: string }> {
  const candidates = [
    'src/db/schema.ts',
    'src/schema.ts',
    'src/drizzle/schema.ts',
    'db/schema.ts',
    'drizzle/schema.ts',
    'schema.ts',
    'src/lib/db/schema.ts',
    'src/server/db/schema.ts',
  ]

  const results: Array<{ path: string; content: string }> = []

  for (const candidate of candidates) {
    const fullPath = resolve(cwd, candidate)
    if (existsSync(fullPath)) {
      const content = readFileSync(fullPath, 'utf-8')
      if (content.includes('pgTable')) {
        results.push({ path: candidate, content })
      }
    }
  }

  // Also scan for pgTable in src/**/*.ts if nothing found yet
  if (results.length === 0) {
    const srcDir = resolve(cwd, 'src')
    if (existsSync(srcDir)) {
      scanForPgTable(srcDir, cwd, results)
    }
    const dbDir = resolve(cwd, 'db')
    if (existsSync(dbDir)) {
      scanForPgTable(dbDir, cwd, results)
    }
  }

  return results
}

/**
 * `pgTable` is a Drizzle import that, when present, is in the file's
 * import block — typically within the first kilobyte. Probing the head of
 * each candidate before reading the full content keeps the recursive
 * scan from loading every TypeScript file in the project into memory on
 * large monorepos.
 */
const PROBE_BYTES = 8192

function fileContainsPgTable(fullPath: string): boolean {
  let fd: number | undefined
  try {
    fd = openSync(fullPath, 'r')
    const buf = Buffer.alloc(PROBE_BYTES)
    const bytesRead = readSync(fd, buf, 0, PROBE_BYTES, 0)
    return buf.subarray(0, bytesRead).includes('pgTable')
  } catch {
    return false
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd)
      } catch {
        // already closed / not openable — nothing to do
      }
    }
  }
}

function scanForPgTable(
  dir: string,
  cwd: string,
  results: Array<{ path: string; content: string }>,
  depth = 0,
): void {
  if (depth > 4) return
  try {
    const entries = readdirSync(dir, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue
      const fullPath = join(dir, entry.name)
      if (entry.isDirectory()) {
        scanForPgTable(fullPath, cwd, results, depth + 1)
      } else if (
        entry.name.endsWith('.ts') &&
        !entry.name.endsWith('.d.ts') &&
        fileContainsPgTable(fullPath)
      ) {
        const content = readFileSync(fullPath, 'utf-8')
        const relativePath = fullPath.slice(cwd.length + 1)
        results.push({ path: relativePath, content })
      }
    }
  } catch {
    // Permission error or similar — skip
  }
}
