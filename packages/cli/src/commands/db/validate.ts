import { resolveDatabaseUrl } from '@/config/database-url.js'
import { loadEncryptConfig, loadStashConfig } from '@/config/index.js'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import * as p from '@clack/prompts'

type Severity = 'error' | 'warning' | 'info'

interface ValidationIssue {
  severity: Severity
  table: string
  column: string
  message: string
}

/** Cast-as types that are not string-like — free-text search is meaningless for these. */
const NON_STRING_CAST_TYPES = new Set([
  'int',
  'small_int',
  'big_int',
  'real',
  'double',
  'boolean',
  'date',
  'number',
  'bigint',
])

/**
 * Validate an EncryptConfig against common misconfiguration rules.
 *
 * This is a pure function so it can be tested and reused (e.g. in `push`).
 */
export function validateEncryptConfig(
  config: EncryptConfig,
  options: { supabase?: boolean; excludeOperatorFamily?: boolean },
): ValidationIssue[] {
  const issues: ValidationIssue[] = []

  for (const [tableName, columns] of Object.entries(config.tables)) {
    for (const [columnName, column] of Object.entries(columns)) {
      const { cast_as, indexes } = column

      // Rule 1: freeTextSearch (match index) on a non-string column
      if (indexes.match && NON_STRING_CAST_TYPES.has(cast_as)) {
        issues.push({
          severity: 'warning',
          table: tableName,
          column: columnName,
          message: `freeTextSearch on a "${cast_as}" column has no effect — free-text search only works with string data`,
        })
      }

      // Rule 2: orderAndRange (ore index) without operator families
      if (indexes.ore && (options.supabase || options.excludeOperatorFamily)) {
        issues.push({
          severity: 'warning',
          table: tableName,
          column: columnName,
          message:
            'orderAndRange index will not support ORDER BY without operator families (Supabase limitation)',
        })
      }

      // Rule 3: No indexes defined — column is encrypted but not searchable
      const hasAnyIndex =
        indexes.ore !== undefined ||
        indexes.unique !== undefined ||
        indexes.match !== undefined ||
        indexes.ste_vec !== undefined
      if (!hasAnyIndex) {
        issues.push({
          severity: 'info',
          table: tableName,
          column: columnName,
          message:
            'Column is encrypted but has no indexes — it will not be searchable',
        })
      }

      // Rule 4: ste_vec index without json data type
      if (indexes.ste_vec && cast_as !== 'json') {
        issues.push({
          severity: 'error',
          table: tableName,
          column: columnName,
          message: `searchableJson requires dataType("json") but found "${cast_as}"`,
        })
      }
    }
  }

  return issues
}

function countTables(config: EncryptConfig): number {
  return Object.keys(config.tables).length
}

function countColumns(config: EncryptConfig): number {
  let count = 0
  for (const columns of Object.values(config.tables)) {
    count += Object.keys(columns).length
  }
  return count
}

/**
 * Print validation issues using `@clack/prompts` log methods.
 *
 * @returns `true` if there are any errors (severity === 'error').
 */
export function reportIssues(issues: ValidationIssue[]): boolean {
  for (const issue of issues) {
    const line = `${issue.table}.${issue.column}: ${issue.message}`

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

export async function validateCommand(options: {
  supabase?: boolean
  excludeOperatorFamily?: boolean
  databaseUrl?: string
}) {
  p.intro('npx @cipherstash/cli db validate')

  await resolveDatabaseUrl({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig()
  s.stop('Configuration loaded.')

  s.start(`Loading encrypt client from ${config.client}...`)
  const encryptConfig = await loadEncryptConfig(config.client)
  s.stop('Encrypt client loaded.')

  if (!encryptConfig) {
    p.log.error('No encryption config found.')
    process.exit(1)
  }

  const tableCount = countTables(encryptConfig)
  const columnCount = countColumns(encryptConfig)
  p.log.success(
    `Schema loaded: ${tableCount} table${tableCount !== 1 ? 's' : ''}, ${columnCount} encrypted column${columnCount !== 1 ? 's' : ''}`,
  )

  const issues = validateEncryptConfig(encryptConfig, options)

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
