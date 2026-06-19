/**
 * MCP wizard-tools server.
 *
 * Exposes tools to the agent for safe environment variable management,
 * package manager detection, and database introspection.
 *
 * Security: secret values never leave the machine. The agent interacts
 * with .env files only through these tools, not through direct file access.
 */

import {
  appendFileSync,
  existsSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { relative, resolve } from 'node:path'
import pg from 'pg'

// --- Security helpers ---

/** Escape regex metacharacters to prevent regex injection. */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Validate that a resolved path stays within the cwd.
 * Prevents path traversal attacks (e.g. ../../etc/passwd).
 */
function assertWithinCwd(cwd: string, filePath: string): void {
  const resolved = resolve(cwd, filePath)
  const rel = relative(cwd, resolved)
  if (
    rel.startsWith('..') ||
    resolve(resolved) !== resolved.replace(/\/$/, '')
  ) {
    throw new Error(
      `Path traversal blocked: ${filePath} resolves outside the project directory.`,
    )
  }
}

// --- Tool: check_env_keys ---

interface CheckEnvKeysInput {
  filePath: string
  keys: string[]
}

interface CheckEnvKeysResult {
  [key: string]: 'present' | 'missing'
}

export function checkEnvKeys(
  cwd: string,
  input: CheckEnvKeysInput,
): CheckEnvKeysResult {
  assertWithinCwd(cwd, input.filePath)
  const envPath = resolve(cwd, input.filePath)
  const result: CheckEnvKeysResult = {}

  let content = ''
  if (existsSync(envPath)) {
    content = readFileSync(envPath, 'utf-8')
  }

  for (const key of input.keys) {
    const pattern = new RegExp(`^${escapeRegex(key)}\\s*=`, 'm')
    result[key] = pattern.test(content) ? 'present' : 'missing'
  }

  return result
}

// --- Tool: set_env_values ---

interface SetEnvValuesInput {
  filePath: string
  values: Record<string, string>
}

export function setEnvValues(cwd: string, input: SetEnvValuesInput): string {
  assertWithinCwd(cwd, input.filePath)
  const envPath = resolve(cwd, input.filePath)

  // Create file if it doesn't exist
  if (!existsSync(envPath)) {
    writeFileSync(envPath, '', 'utf-8')
  }

  let content = readFileSync(envPath, 'utf-8')
  let updated = 0

  for (const [key, value] of Object.entries(input.values)) {
    const pattern = new RegExp(`^${escapeRegex(key)}\\s*=.*$`, 'm')

    if (pattern.test(content)) {
      content = content.replace(pattern, `${key}=${value}`)
    } else {
      content += `${content.endsWith('\n') || content.length === 0 ? '' : '\n'}${key}=${value}\n`
    }
    updated++
  }

  writeFileSync(envPath, content, 'utf-8')

  // Ensure .gitignore coverage
  ensureGitignore(cwd, input.filePath)

  return `Updated ${updated} environment variable${updated !== 1 ? 's' : ''} in ${input.filePath}`
}

function ensureGitignore(cwd: string, envFile: string) {
  const gitignorePath = resolve(cwd, '.gitignore')

  if (!existsSync(gitignorePath)) return

  const content = readFileSync(gitignorePath, 'utf-8')
  if (!content.includes(envFile)) {
    appendFileSync(gitignorePath, `\n${envFile}\n`)
  }
}

// --- Tool: detect_package_manager ---

import { detectPackageManager as detect } from '../lib/detect.js'

export function detectPackageManagerTool(cwd: string) {
  const pm = detect(cwd)
  if (!pm) {
    return { detected: false, message: 'No package manager detected.' }
  }

  return {
    detected: true,
    name: pm.name,
    installCommand: pm.installCommand,
    runCommand: pm.runCommand,
  }
}

// --- Tool: introspect_database ---

interface DbColumn {
  columnName: string
  dataType: string
  udtName: string
  isEqlEncrypted: boolean
}

interface DbTable {
  tableName: string
  columns: DbColumn[]
}

export async function introspectDatabase(
  databaseUrl: string,
): Promise<DbTable[]> {
  const client = new pg.Client({ connectionString: databaseUrl })
  try {
    await client.connect()

    const { rows } = await client.query<{
      table_name: string
      column_name: string
      data_type: string
      udt_name: string
    }>(`
      SELECT c.table_name, c.column_name, c.data_type, c.udt_name
      FROM information_schema.columns c
      JOIN information_schema.tables t
        ON t.table_name = c.table_name AND t.table_schema = c.table_schema
      WHERE c.table_schema = 'public'
        AND t.table_type = 'BASE TABLE'
      ORDER BY c.table_name, c.ordinal_position
    `)

    const tableMap = new Map<string, DbColumn[]>()
    for (const row of rows) {
      const cols = tableMap.get(row.table_name) ?? []
      cols.push({
        columnName: row.column_name,
        dataType: row.data_type,
        udtName: row.udt_name,
        isEqlEncrypted: row.udt_name === 'eql_v2_encrypted',
      })
      tableMap.set(row.table_name, cols)
    }

    return Array.from(tableMap.entries()).map(([tableName, columns]) => ({
      tableName,
      columns,
    }))
  } finally {
    await client.end()
  }
}
