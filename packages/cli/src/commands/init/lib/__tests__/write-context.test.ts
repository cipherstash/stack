import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  CONTEXT_REL_PATH,
  type ContextFile,
  writeBaselineContextFile,
} from '../write-context.js'

let cwd: string

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'stash-write-context-'))
})

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true })
})

function readContext(): ContextFile {
  return JSON.parse(readFileSync(join(cwd, CONTEXT_REL_PATH), 'utf-8'))
}

describe('writeBaselineContextFile', () => {
  /**
   * `installedSkills` used to be hardcoded `[]` in `buildContextFile`, set
   * only by the handoff steps — so every `context.json` written by `stash
   * init` reported no skills regardless of what was on disk. That empty
   * array is the artifact #923 was diagnosed from, and the reason the bug
   * survived a release: the file looked plausible.
   */
  it('reports the skills the init step installed', () => {
    writeBaselineContextFile(
      {
        integration: 'supabase',
        skills: {
          installed: ['stash-supabase', 'stash-cli'],
          inlined: [],
          failed: [],
        },
      },
      cwd,
      ['DATABASE_URL'],
    )

    const ctx = readContext()
    expect(ctx.installedSkills).toEqual(['stash-supabase', 'stash-cli'])
    expect(ctx.envKeys).toEqual(['DATABASE_URL'])
  })

  it('reports an empty list when nothing was installed', () => {
    writeBaselineContextFile({ integration: 'drizzle' }, cwd, [])
    expect(readContext().installedSkills).toEqual([])
  })
})
