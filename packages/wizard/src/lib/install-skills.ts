import { cpSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as p from '@clack/prompts'
import type { Integration } from './types.js'

/**
 * Which bundled skills are relevant for each wizard integration. These ship
 * alongside the CLI (see `tsup.config.ts` — `skills/` is copied into
 * `dist/skills/` at build time). The wizard offers to copy the matching
 * skills into the user's project so Claude Code picks them up during
 * follow-up work.
 */
const SKILL_MAP: Record<Integration, readonly string[]> = {
  drizzle: ['stash-encryption', 'stash-drizzle', 'stash-cli'],
  supabase: ['stash-encryption', 'stash-supabase', 'stash-cli'],
  prisma: ['stash-encryption', 'stash-cli'],
  generic: ['stash-encryption', 'stash-cli'],
}

/**
 * Outcome of {@link maybeInstallSkills}. `copied` and `failed` partition the
 * skills the user confirmed: both empty means declined, nothing bundled, or
 * nothing to copy; `failed` non-empty means the user said yes but the
 * filesystem said no — the caller should record that, since the transient
 * terminal warning is the only other evidence.
 */
export interface SkillsInstallResult {
  copied: string[]
  failed: string[]
}

/**
 * Prompt the user, and if they say yes, copy the selected skills into
 * `<cwd>/.claude/skills/<skill-name>/`.
 */
export async function maybeInstallSkills(
  cwd: string,
  integration: Integration,
): Promise<SkillsInstallResult> {
  const skills = SKILL_MAP[integration] ?? SKILL_MAP.generic
  const bundledRoot = resolveBundledSkillsRoot()
  if (!bundledRoot) {
    p.log.warn(
      'Skills bundle not found in this CLI build — skipping skills install.',
    )
    return { copied: [], failed: [] }
  }

  const available = skills.filter((name) => existsSync(join(bundledRoot, name)))
  if (available.length === 0) return { copied: [], failed: [] }

  const confirmed = await p.confirm({
    message: `Install ${available.length} Claude skill(s) into ./.claude/skills/ (${available.join(', ')})?`,
    initialValue: true,
  })
  if (p.isCancel(confirmed) || !confirmed) return { copied: [], failed: [] }

  const destRoot = resolve(cwd, '.claude', 'skills')
  try {
    mkdirSync(destRoot, { recursive: true })
  } catch (err) {
    // Guarded for the same reason as the copy loop below, which it sat above
    // unprotected: an unwritable destination (read-only mount, restrictive
    // permissions, a sandbox) threw past every fallback and took the caller
    // with it. The `stash` copy of this function hit exactly that on
    // `.codex/skills` — see cipherstash/stack#736. Degrade to "no skills"
    // instead; the wizard's remaining output is still useful.
    const message = err instanceof Error ? err.message : String(err)
    p.log.warn(`Could not create ./.claude/skills/: ${message}`)
    return { copied: [], failed: available }
  }

  const copied: string[] = []
  const failed: string[] = []
  for (const name of available) {
    const src = join(bundledRoot, name)
    const dest = join(destRoot, name)
    try {
      cpSync(src, dest, { recursive: true, force: true })
      copied.push(name)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      p.log.warn(`Failed to install skill ${name}: ${message}`)
      failed.push(name)
    }
  }

  if (copied.length > 0) {
    p.log.success(
      `Installed ${copied.length} skill(s) into ./.claude/skills/: ${copied.join(', ')}`,
    )
  }

  return { copied, failed }
}

/**
 * Locate the `skills/` directory bundled with this CLI. `tsup` copies the
 * monorepo's top-level `skills/` into `dist/skills/`, so the build sits
 * alongside the compiled binary regardless of where pnpm/npm installs it.
 *
 * Walks up from the current file looking for a sibling `skills` dir so
 * both the library entry (`dist/index.js`) and the CLI entry
 * (`dist/bin/stash.js`) can find it.
 */
function resolveBundledSkillsRoot(): string | undefined {
  const here = currentDir()
  const candidates = [
    join(here, 'skills'),
    join(here, '..', 'skills'),
    join(here, '..', '..', 'skills'),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) return resolve(candidate)
  }
  return undefined
}

function currentDir(): string {
  if (typeof import.meta?.url === 'string' && import.meta.url) {
    return dirname(fileURLToPath(import.meta.url))
  }
  return __dirname
}
