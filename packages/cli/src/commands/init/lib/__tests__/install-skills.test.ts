import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  installSkills,
  readBundledSkill,
  SKILL_MAP,
} from '../install-skills.js'

describe('SKILL_MAP', () => {
  it('always includes stash-encryption and stash-cli for every integration', () => {
    for (const [integration, skills] of Object.entries(SKILL_MAP)) {
      expect(skills, integration).toContain('stash-encryption')
      expect(skills, integration).toContain('stash-cli')
    }
  })

  it('drizzle includes stash-drizzle', () => {
    expect(SKILL_MAP.drizzle).toContain('stash-drizzle')
  })

  it('supabase includes stash-supabase', () => {
    expect(SKILL_MAP.supabase).toContain('stash-supabase')
  })

  it('postgresql skips ORM-specific skills', () => {
    expect(SKILL_MAP.postgresql).not.toContain('stash-drizzle')
    expect(SKILL_MAP.postgresql).not.toContain('stash-supabase')
  })
})

describe('installSkills', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'install-skills-test-'))
  })

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('copies the per-integration skills into destDir', () => {
    const copied = installSkills(tmp, '.claude/skills', 'drizzle')
    expect(copied).toEqual(['stash-encryption', 'stash-drizzle', 'stash-cli'])
    for (const name of copied) {
      expect(
        existsSync(join(tmp, '.claude/skills', name, 'SKILL.md')),
        `${name}/SKILL.md should be present`,
      ).toBe(true)
    }
  })

  it('honours the destDir parameter (codex)', () => {
    const copied = installSkills(tmp, '.codex/skills', 'supabase')
    expect(copied).toContain('stash-supabase')
    expect(existsSync(join(tmp, '.codex/skills/stash-supabase/SKILL.md'))).toBe(
      true,
    )
    // Does not write to .claude/ when codex is the target.
    expect(existsSync(join(tmp, '.claude'))).toBe(false)
  })

  it('is idempotent — re-running does not throw and yields the same result', () => {
    const first = installSkills(tmp, '.claude/skills', 'postgresql')
    const second = installSkills(tmp, '.claude/skills', 'postgresql')
    expect(second).toEqual(first)
  })

  it('writes SKILL.md content from the bundled source', () => {
    installSkills(tmp, '.claude/skills', 'drizzle')
    const content = readFileSync(
      join(tmp, '.claude/skills/stash-encryption/SKILL.md'),
      'utf-8',
    )
    expect(content).toMatch(/^---/)
    expect(content).toContain('name: stash-encryption')
  })
})

describe('readBundledSkill', () => {
  it('returns the SKILL.md body for a bundled skill', () => {
    const body = readBundledSkill('stash-encryption')
    expect(body).toBeDefined()
    expect(body).toContain('name: stash-encryption')
  })

  it('returns undefined for an unknown skill name', () => {
    expect(readBundledSkill('does-not-exist')).toBeUndefined()
  })
})
