import { cpSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import * as p from '@clack/prompts'
import type { Integration } from '../types.js'
import { findBundledDir } from './bundled-paths.js'

/**
 * Per-integration set of skills to install. The skills themselves live at
 * the monorepo root in `/skills/<name>/SKILL.md` and ship inside the CLI
 * tarball — see `tsup.config.ts`, which copies the directory into
 * `dist/skills/` at build time.
 */
export const SKILL_MAP: Record<Integration, readonly string[]> = {
  drizzle: ['stash-encryption', 'stash-drizzle', 'stash-cli'],
  supabase: ['stash-encryption', 'stash-supabase', 'stash-cli'],
  'prisma-next': ['stash-encryption', 'stash-prisma-next', 'stash-cli'],
  postgresql: ['stash-encryption', 'stash-cli'],
}

/** The skills every integration gets — the safe fallback for an unmapped one. */
const BASE_SKILLS: readonly string[] = ['stash-encryption', 'stash-cli']

/**
 * Skills for an integration, resilient to an unmapped one. `SKILL_MAP` is
 * typed `Record<Integration, …>`, but the build (`tsup`) transpiles without
 * type-checking — so a new `Integration` variant added without a `SKILL_MAP`
 * entry would ship as `undefined` and crash both consumers (`installSkills`,
 * the AGENTS.md builder) with "not iterable". Degrade to the base skill set
 * instead: the user still gets `stash-encryption` + `stash-cli`, never a
 * stack trace. (Regression-guarded by a test asserting SKILL_MAP has a
 * non-empty entry for every value in a maintained `ALL_INTEGRATIONS` list.)
 */
export function skillsFor(integration: Integration): readonly string[] {
  return SKILL_MAP[integration] ?? BASE_SKILLS
}

/**
 * Copy the per-integration set of skills into `<cwd>/<destDir>/<skill>/`.
 *
 * Unlike the wizard's variant, this does NOT prompt — by the time it runs,
 * the user has already picked a handoff and the skills are part of that
 * choice. Returns the names of skills actually copied.
 *
 * `destDir` is relative to `cwd` and dictates the per-tool location:
 *   `.claude/skills` for Claude Code, `.codex/skills` for Codex.
 *
 * Idempotent: re-runs overwrite the skill folders so the user always gets
 * the latest content shipped with this CLI.
 */
export function installSkills(
  cwd: string,
  destDir: string,
  integration: Integration,
): string[] {
  const skills = skillsFor(integration)
  const bundledRoot = findBundledDir('skills')
  if (!bundledRoot) {
    p.log.warn(
      'Skills bundle not found in this CLI build — skipping skills install.',
    )
    return []
  }

  const available = skills.filter((name) => existsSync(join(bundledRoot, name)))
  if (available.length === 0) return []

  const destRoot = resolve(cwd, destDir)
  mkdirSync(destRoot, { recursive: true })

  const copied: string[] = []
  for (const name of available) {
    const src = join(bundledRoot, name)
    const dest = join(destRoot, name)
    try {
      cpSync(src, dest, { recursive: true, force: true })
      copied.push(name)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      p.log.warn(`Failed to install skill ${name}: ${message}`)
    }
  }

  return copied
}

/**
 * Read the body of a single bundled skill's SKILL.md. Used by the AGENTS.md
 * builder when the handoff target is an editor agent (Cursor / Windsurf /
 * Cline) that doesn't auto-load skill directories — we inline the content.
 *
 * Returns undefined if the bundle isn't found or the named skill isn't part
 * of the bundle. Callers should treat that as "skip this skill" rather than
 * a fatal error so a stripped CLI build still produces a usable AGENTS.md.
 */
export function readBundledSkill(name: string): string | undefined {
  const bundledRoot = findBundledDir('skills')
  if (!bundledRoot) return undefined
  const skillFile = join(bundledRoot, name, 'SKILL.md')
  if (!existsSync(skillFile)) return undefined
  return readFileSync(skillFile, 'utf-8')
}
