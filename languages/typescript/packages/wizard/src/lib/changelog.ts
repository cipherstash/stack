import { existsSync, mkdirSync } from 'node:fs'
import { appendFile, readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

/**
 * Local markdown log the wizard writes to `<cwd>/.cipherstash/wizard-log.md`
 * after each run. Captures the sequence of decisions and file touches so
 * future agents (and humans) have a record of what happened (CIP-2993).
 *
 * Appended to, never overwritten — each wizard invocation starts a fresh
 * section delimited by a timestamp header.
 */
export class WizardChangelog {
  private readonly entries: ChangelogEntry[] = []
  private readonly startedAt = new Date()

  constructor(private readonly cwd: string) {}

  record(entry: ChangelogEntry): void {
    this.entries.push(entry)
  }

  phase(name: string, detail?: string): void {
    this.record({ kind: 'phase', name, detail })
  }

  action(description: string, files?: string[]): void {
    this.record({ kind: 'action', description, files })
  }

  note(text: string): void {
    this.record({ kind: 'note', text })
  }

  /**
   * Serialize the collected entries and append to `<cwd>/.cipherstash/wizard-log.md`.
   * Safe to call multiple times — only appends new content.
   */
  async flush(): Promise<string | undefined> {
    if (this.entries.length === 0) return undefined

    const dir = resolve(this.cwd, '.cipherstash')
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    const path = join(dir, 'wizard-log.md')

    const isNew = !existsSync(path)
    const header = isNew ? '# CipherStash Wizard log\n\n' : ''
    const body = this.render()

    if (isNew) {
      await writeFile(path, header + body, 'utf-8')
    } else {
      await appendFile(path, body, 'utf-8')
    }

    return path
  }

  /** Inspect the most recent persisted log, for tests or debug. */
  async readExisting(): Promise<string | undefined> {
    const path = join(resolve(this.cwd, '.cipherstash'), 'wizard-log.md')
    if (!existsSync(path)) return undefined
    return readFile(path, 'utf-8')
  }

  private render(): string {
    const header = `## Run ${this.startedAt.toISOString()}\n\n`
    const lines: string[] = [header]
    for (const entry of this.entries) {
      lines.push(renderEntry(entry))
    }
    lines.push('')
    return lines.join('\n')
  }
}

function renderEntry(entry: ChangelogEntry): string {
  switch (entry.kind) {
    case 'phase':
      return entry.detail
        ? `### ${entry.name}\n\n${entry.detail}\n`
        : `### ${entry.name}\n`
    case 'action': {
      const filesBlock = entry.files?.length
        ? `\n${entry.files.map((f) => `  - \`${f}\``).join('\n')}\n`
        : ''
      return `- ${entry.description}${filesBlock}`
    }
    case 'note':
      return `> ${entry.text}\n`
  }
}

type ChangelogEntry =
  | { kind: 'phase'; name: string; detail?: string }
  | { kind: 'action'; description: string; files?: string[] }
  | { kind: 'note'; text: string }
