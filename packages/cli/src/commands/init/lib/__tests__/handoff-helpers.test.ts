import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mergeSkillsDelivery } from '../../types.js'

vi.mock('@clack/prompts', () => ({
  log: { warn: vi.fn(), success: vi.fn(), info: vi.fn() },
}))

import { writeArtifacts } from '../handoff-helpers.js'
import { CONTEXT_REL_PATH, type ContextFile } from '../write-context.js'

let cwd: string

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'stash-handoff-'))
})

afterEach(() => {
  vi.restoreAllMocks()
  rmSync(cwd, { recursive: true, force: true })
})

function readContext(): ContextFile {
  return JSON.parse(readFileSync(join(cwd, CONTEXT_REL_PATH), 'utf-8'))
}

describe('mergeSkillsDelivery', () => {
  it('unions both sides and de-duplicates', () => {
    expect(
      mergeSkillsDelivery(
        { installed: ['a', 'b'], inlined: [], failed: [] },
        { installed: ['b', 'c'], inlined: ['d'], failed: [] },
      ),
    ).toEqual({ installed: ['a', 'b', 'c'], inlined: ['d'], failed: [] })
  })

  // A skill that failed one hop and landed in another is delivered. Leaving it
  // in `failed` would have the record report it as both.
  it('drops a failure that a later hop delivered', () => {
    expect(
      mergeSkillsDelivery(
        { installed: [], inlined: [], failed: ['stash-cli'] },
        { installed: [], inlined: ['stash-cli'], failed: [] },
      ),
    ).toEqual({ installed: [], inlined: ['stash-cli'], failed: [] })
  })

  it('treats an absent left side as empty', () => {
    expect(
      mergeSkillsDelivery(undefined, {
        installed: ['a'],
        inlined: [],
        failed: [],
      }),
    ).toEqual({ installed: ['a'], inlined: [], failed: [] })
  })
})

describe('writeArtifacts', () => {
  /**
   * The #923 regression, one command later. `stash init` installs skills into
   * `.claude/skills/` up front; a subsequent `stash plan --target agents-md`
   * installs no directories of its own and used to overwrite
   * `installedSkills` with its own empty list — erasing from the record
   * skills that are sitting on disk.
   */
  it('keeps skills a previous hop installed', () => {
    writeArtifacts(
      cwd,
      {
        integration: 'supabase',
        skills: {
          installed: ['stash-encryption', 'stash-cli'],
          inlined: [],
          failed: [],
        },
      },
      'agents-md',
      { installed: [], inlined: ['stash-supabase'], failed: [] },
    )

    const ctx = readContext()
    expect(ctx.installedSkills).toEqual(['stash-encryption', 'stash-cli'])
    expect(ctx.inlinedSkills).toEqual(['stash-supabase'])
  })

  it('records this hop when there is nothing to merge with', () => {
    writeArtifacts(cwd, { integration: 'drizzle' }, 'claude-code', {
      installed: ['stash-drizzle'],
      inlined: [],
      failed: [],
    })

    expect(readContext().installedSkills).toEqual(['stash-drizzle'])
  })
})
