import { describe, expect, it } from 'vitest'
import { buildAgentsMdBody } from '../build-agents-md.js'

describe('buildAgentsMdBody', () => {
  it('returns content WITHOUT sentinel wrappers (upsertManagedBlock owns those)', () => {
    // Regression guard: if buildAgentsMdBody emits sentinels itself,
    // upsertManagedBlock will wrap them again and produce a malformed
    // file on the second init run.
    const out = buildAgentsMdBody('drizzle', 'doctrine-only')
    expect(out).not.toContain('<!-- cipherstash:rulebook start -->')
    expect(out).not.toContain('<!-- cipherstash:rulebook end -->')
  })

  it('doctrine-only includes the durable doctrine but no skill content', () => {
    const out = buildAgentsMdBody('drizzle', 'doctrine-only')
    expect(out).toContain('# CipherStash')
    // Doctrine references invariants — pick a stable phrase that's unlikely
    // to drift across rewrites.
    expect(out).toMatch(/Never log plaintext/)
    // Inlined skill markers should NOT appear.
    expect(out).not.toContain('# Skill: stash-encryption')
    expect(out).not.toContain('# Skill: stash-drizzle')
  })

  it('doctrine-plus-skills inlines the per-integration skills', () => {
    const out = buildAgentsMdBody('drizzle', 'doctrine-plus-skills')
    expect(out).toContain('# CipherStash')
    expect(out).toContain('# Skill: stash-encryption')
    expect(out).toContain('# Skill: stash-drizzle')
    expect(out).toContain('# Skill: stash-cli')
    // Frontmatter from individual skill files should be stripped — the
    // `name: <skill>` line is part of YAML frontmatter and should not leak.
    expect(out).not.toMatch(/^---\nname: stash-encryption/m)
  })

  it('inlines a different skill set per integration', () => {
    const drizzleOut = buildAgentsMdBody('drizzle', 'doctrine-plus-skills')
    const supabaseOut = buildAgentsMdBody('supabase', 'doctrine-plus-skills')

    expect(drizzleOut).toContain('# Skill: stash-drizzle')
    expect(drizzleOut).not.toContain('# Skill: stash-supabase')

    expect(supabaseOut).toContain('# Skill: stash-supabase')
    expect(supabaseOut).not.toContain('# Skill: stash-drizzle')
  })

  it('postgresql integration omits ORM-specific skills', () => {
    const out = buildAgentsMdBody('postgresql', 'doctrine-plus-skills')
    expect(out).toContain('# Skill: stash-encryption')
    expect(out).toContain('# Skill: stash-cli')
    expect(out).not.toContain('# Skill: stash-drizzle')
    expect(out).not.toContain('# Skill: stash-supabase')
  })

  it('prisma-next inlines the stash-prisma-next skill (no crash on undefined map)', () => {
    // Regression: SKILL_MAP once lacked a prisma-next key, so this call
    // threw "SKILL_MAP[integration] is not iterable" for any Prisma repo.
    const out = buildAgentsMdBody('prisma-next', 'doctrine-plus-skills')
    expect(out).toContain('# Skill: stash-prisma-next')
    expect(out).toContain('# Skill: stash-encryption')
    expect(out).not.toContain('# Skill: stash-drizzle')
  })

  it('inlines only the requested subset when a skill list is passed', () => {
    // The Codex fallback passes just the skills that failed to copy, so a
    // partial install inlines exactly the missing ones (#736 follow-up).
    const out = buildAgentsMdBody('drizzle', 'doctrine-plus-skills', [
      'stash-cli',
    ])
    expect(out).toContain('# Skill: stash-cli')
    expect(out).not.toContain('# Skill: stash-encryption')
    expect(out).not.toContain('# Skill: stash-drizzle')
  })
})
