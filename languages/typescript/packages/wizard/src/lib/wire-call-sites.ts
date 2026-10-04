import { glob, readFile } from 'node:fs/promises'
import { relative } from 'node:path'
import type { Integration } from './types.js'

/**
 * After the agent converts a user's Drizzle/Supabase schemas to encrypted
 * columns, their existing server-action / page / API-route code still
 * treats those fields as plain text or numbers. We can't safely rewrite
 * those call sites automatically (risk is too high and agents can reason
 * about the domain better than a regex), but we can point the user at every
 * place that needs attention — that's the goal of this report. CIP-2995.
 *
 * This module is intentionally **report-only**: we read files, print a
 * summary, and write the same summary into the wizard log. No mutations.
 */

export interface CallSiteMatch {
  file: string
  line: number
  snippet: string
  kind: 'insert' | 'update' | 'select'
}

/**
 * Scan the project for places that insert/update/select rows on one of the
 * tables the user encrypted, so we can tell them to wrap those calls with
 * `encryptModel` / `decryptModel`.
 *
 * The patterns are conservative on purpose — false positives clutter the
 * report, so we only match the common idioms. Users with custom query
 * builders will see a smaller report and get pointed at the docs.
 */
export async function scanCallSites(
  cwd: string,
  tables: readonly string[],
  integration: Integration,
): Promise<CallSiteMatch[]> {
  if (tables.length === 0) return []

  const files: string[] = []
  const patterns = [
    'src/app/**/*.ts',
    'src/app/**/*.tsx',
    'src/lib/**/*.ts',
    'src/lib/**/*.tsx',
    'app/**/*.ts',
    'app/**/*.tsx',
    'lib/**/*.ts',
    'lib/**/*.tsx',
  ]
  for (const pattern of patterns) {
    for await (const match of glob(pattern, { cwd })) {
      files.push(match)
    }
  }

  const results: CallSiteMatch[] = []

  for (const relPath of files) {
    const absPath = `${cwd.replace(/\/$/, '')}/${relPath}`
    let text: string
    try {
      text = await readFile(absPath, 'utf-8')
    } catch {
      continue
    }

    const matches = findMatches(text, tables, integration)
    for (const m of matches) {
      results.push({ ...m, file: relative(cwd, absPath) })
    }
  }

  return results
}

function findMatches(
  source: string,
  tables: readonly string[],
  integration: Integration,
): Array<Omit<CallSiteMatch, 'file'>> {
  const lines = source.split('\n')
  const out: Array<Omit<CallSiteMatch, 'file'>> = []

  const tablesPattern = tables.map(escapeRegex).join('|')
  if (!tablesPattern) return out

  // Drizzle idioms: `db.insert(foo)`, `db.update(foo).set(`, `.from(foo)`.
  // Supabase idioms: `.from('foo').insert(`, `.from('foo').update(`,
  // `.from('foo').select(`.
  const drizzleInsert = new RegExp(`\\.insert\\(\\s*(?:${tablesPattern})\\b`)
  const drizzleUpdate = new RegExp(`\\.update\\(\\s*(?:${tablesPattern})\\b`)
  const drizzleSelect = new RegExp(`\\.from\\(\\s*(?:${tablesPattern})\\b`)

  const supabaseFromInsert = new RegExp(
    `\\.from\\(\\s*['"\`](?:${tablesPattern})['"\`]\\s*\\)[\\s\\S]{0,80}?\\.insert\\b`,
  )
  const supabaseFromUpdate = new RegExp(
    `\\.from\\(\\s*['"\`](?:${tablesPattern})['"\`]\\s*\\)[\\s\\S]{0,80}?\\.update\\b`,
  )
  const supabaseFromSelect = new RegExp(
    `\\.from\\(\\s*['"\`](?:${tablesPattern})['"\`]\\s*\\)[\\s\\S]{0,80}?\\.select\\b`,
  )

  lines.forEach((line, i) => {
    if (integration === 'drizzle') {
      if (drizzleInsert.test(line))
        out.push({ kind: 'insert', line: i + 1, snippet: line.trim() })
      if (drizzleUpdate.test(line))
        out.push({ kind: 'update', line: i + 1, snippet: line.trim() })
      if (drizzleSelect.test(line))
        out.push({ kind: 'select', line: i + 1, snippet: line.trim() })
    } else if (integration === 'supabase') {
      if (supabaseFromInsert.test(line))
        out.push({ kind: 'insert', line: i + 1, snippet: line.trim() })
      if (supabaseFromUpdate.test(line))
        out.push({ kind: 'update', line: i + 1, snippet: line.trim() })
      if (supabaseFromSelect.test(line))
        out.push({ kind: 'select', line: i + 1, snippet: line.trim() })
    }
  })

  return out
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Render the scan result as a multi-line markdown section, ready for both
 * terminal output and persistence into the wizard log.
 */
export function renderCallSiteReport(
  matches: readonly CallSiteMatch[],
): string {
  if (matches.length === 0) {
    return 'No encrypted-table call sites found in src/app, src/lib, app/, or lib/.'
  }

  const byFile = new Map<string, CallSiteMatch[]>()
  for (const m of matches) {
    const list = byFile.get(m.file) ?? []
    list.push(m)
    byFile.set(m.file, list)
  }

  const lines: string[] = []
  lines.push(
    `Found ${matches.length} call site(s) that may need encryptModel/decryptModel wiring:`,
  )
  lines.push('')
  for (const [file, fileMatches] of byFile) {
    lines.push(`- \`${file}\``)
    for (const m of fileMatches) {
      lines.push(`  - line ${m.line} (${m.kind}): \`${m.snippet}\``)
    }
  }
  lines.push('')
  lines.push('Recommended pattern:')
  lines.push('```ts')
  lines.push('// Writes: encrypt before hitting the DB.')
  lines.push(
    'const encrypted = (await encryptionClient.encryptModel(plain, table).run()).data',
  )
  lines.push('')
  lines.push('// Reads: decrypt after the DB returns.')
  lines.push(
    'const plain = (await encryptionClient.decryptModel(row).run()).data',
  )
  lines.push('```')

  return lines.join('\n')
}
