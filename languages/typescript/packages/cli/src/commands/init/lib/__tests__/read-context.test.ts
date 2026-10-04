import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { readContextFile } from '../read-context.js'

let cwd: string

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'stash-context-'))
})

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true })
})

function writeContext(payload: Record<string, unknown>): void {
  mkdirSync(join(cwd, '.cipherstash'), { recursive: true })
  writeFileSync(
    join(cwd, '.cipherstash', 'context.json'),
    JSON.stringify(payload),
    'utf-8',
  )
}

describe('readContextFile', () => {
  it('returns undefined when context.json is missing', () => {
    expect(readContextFile(cwd)).toBeUndefined()
  })

  it('returns the parsed context when present', () => {
    writeContext({
      cliVersion: '0.0.0',
      integration: 'drizzle',
      encryptionClientPath: './src/encryption/index.ts',
      packageManager: 'pnpm',
      installCommand: 'pnpm add @cipherstash/stack',
      envKeys: [],
      schemas: [],
      installedSkills: [],
      inlinedSkills: [],
      generatedAt: '2026-01-01T00:00:00.000Z',
    })
    const ctx = readContextFile(cwd)
    expect(ctx?.integration).toBe('drizzle')
    expect(ctx?.packageManager).toBe('pnpm')
  })

  it('returns undefined on malformed JSON rather than throwing', () => {
    mkdirSync(join(cwd, '.cipherstash'), { recursive: true })
    writeFileSync(
      join(cwd, '.cipherstash', 'context.json'),
      '{ not json',
      'utf-8',
    )
    expect(readContextFile(cwd)).toBeUndefined()
  })

  it('returns undefined for an empty object — wrong shape, not "initialized"', () => {
    // A `{}` file parses fine but doesn't carry `schemas`/`integration`/
    // `packageManager`. Downstream code (status, plan summary, etc.)
    // dereferences those without guarding, so accepting `{}` would mean
    // a hand-edited or partial-write file crashes the CLI.
    writeContext({})
    expect(readContextFile(cwd)).toBeUndefined()
  })

  it('returns undefined when schemas is missing', () => {
    writeContext({
      integration: 'drizzle',
      packageManager: 'pnpm',
      // schemas absent
    })
    expect(readContextFile(cwd)).toBeUndefined()
  })

  it('returns undefined when integration is the wrong type', () => {
    writeContext({
      integration: 42,
      packageManager: 'pnpm',
      schemas: [],
    })
    expect(readContextFile(cwd)).toBeUndefined()
  })

  it('returns undefined when schemas is not an array', () => {
    writeContext({
      integration: 'drizzle',
      packageManager: 'pnpm',
      schemas: 'oops',
    })
    expect(readContextFile(cwd)).toBeUndefined()
  })
})
