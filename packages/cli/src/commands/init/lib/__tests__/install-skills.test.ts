import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { Integration } from '../../types.js'
import {
  availableSkills,
  installSkills,
  readBundledSkill,
  SKILL_MAP,
  skillsFor,
} from '../install-skills.js'

// Every integration the init flow can resolve to. Kept in lockstep with the
// `Integration` union and the init provider registry — a new integration added
// without a SKILL_MAP entry crashes the skills install and the AGENTS.md builder
// (SKILL_MAP[integration] is undefined → "not iterable"), and `tsup` ships that
// without type-checking, so this list is the runtime guard tsc can't be.
const ALL_INTEGRATIONS: Integration[] = [
  'drizzle',
  'supabase',
  'prisma-next',
  'postgresql',
]

describe('SKILL_MAP', () => {
  it('has a non-empty entry for every integration (no undefined → crash)', () => {
    for (const integration of ALL_INTEGRATIONS) {
      const skills = SKILL_MAP[integration]
      expect(skills, integration).toBeDefined()
      expect(skills.length, integration).toBeGreaterThan(0)
    }
  })

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

  it('prisma-next includes stash-prisma-next', () => {
    expect(SKILL_MAP['prisma-next']).toContain('stash-prisma-next')
  })

  it('postgresql skips ORM-specific skills', () => {
    expect(SKILL_MAP.postgresql).not.toContain('stash-drizzle')
    expect(SKILL_MAP.postgresql).not.toContain('stash-supabase')
    expect(SKILL_MAP.postgresql).not.toContain('stash-prisma-next')
  })
})

describe('skillsFor', () => {
  it('returns the mapped skills for a known integration', () => {
    expect(skillsFor('prisma-next')).toEqual([
      'stash-encryption',
      'stash-prisma-next',
      'stash-cli',
    ])
  })

  it('falls back to the base skills for an unmapped integration (never crashes)', () => {
    // Simulate a future Integration variant with no SKILL_MAP entry.
    const skills = skillsFor('mystery-orm' as Integration)
    expect(skills).toEqual(['stash-encryption', 'stash-cli'])
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

  // #736: a Codex sandbox denies writes under `.codex/`, and the unguarded
  // `mkdirSync` threw PAST the per-skill fallback and past the caller — so the
  // whole handoff step died and AGENTS.md / .cipherstash were never written.
  // Degrading to `[]` is what lets the caller fall back to inlining.
  it('returns [] instead of throwing when destDir cannot be created', () => {
    // A FILE where the skills directory needs to be: mkdirSync recursive
    // fails with ENOTDIR/EEXIST rather than succeeding.
    mkdirSync(join(tmp, '.codex'), { recursive: true })
    writeFileSync(join(tmp, '.codex/skills'), 'not a directory', 'utf-8')

    let copied: string[] | undefined
    expect(() => {
      copied = installSkills(tmp, '.codex/skills', 'drizzle')
    }).not.toThrow()
    expect(copied).toEqual([])
  })

  it('leaves the caller able to distinguish "unwritable" from "nothing to install"', () => {
    // `availableSkills` reports what the BUNDLE has, independent of whether
    // the destination could be written — the signal the Codex handoff uses to
    // decide whether an inline fallback is honest.
    mkdirSync(join(tmp, '.codex'), { recursive: true })
    writeFileSync(join(tmp, '.codex/skills'), 'not a directory', 'utf-8')

    expect(installSkills(tmp, '.codex/skills', 'drizzle')).toEqual([])
    expect(availableSkills('drizzle')).toEqual([
      'stash-encryption',
      'stash-drizzle',
      'stash-cli',
    ])
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
