import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import * as p from '@clack/prompts'
import type { Integration } from '../types.js'
import { findBundledDir } from './bundled-paths.js'
import { readBundledSkill, skillsFor } from './install-skills.js'

export type AgentsMdMode = 'doctrine-only' | 'doctrine-plus-skills'

/**
 * Render the managed body of `AGENTS.md` (the bit that goes *inside* the
 * sentinel block — the caller is responsible for the upsert via
 * `upsertManagedBlock`, which owns the sentinel pair). This function must
 * NOT emit sentinels itself or we get nested sentinels and a malformed
 * file on the second init run.
 *
 *   doctrine-only         — the durable AGENTS.md doctrine file. Used by
 *                           the Codex handoff, where workflows live in
 *                           `.codex/skills/` and AGENTS.md is reserved for
 *                           durable rules per OpenAI's Codex guidance.
 *
 *   doctrine-plus-skills  — doctrine + the relevant skill SKILL.md bodies
 *                           inlined under "## Skill references". Used by
 *                           the AGENTS.md handoff for editor agents
 *                           (Cursor / Windsurf / Cline) that don't auto-
 *                           load skill directories.
 */
export function buildAgentsMdBody(
  integration: Integration,
  mode: AgentsMdMode,
): string {
  const doctrine = readDoctrine()
  if (!doctrine) {
    p.log.warn(
      'AGENTS.md doctrine fragment not found in this CLI build — writing a minimal AGENTS.md.',
    )
    return '# CipherStash\n\nSee `.cipherstash/setup-prompt.md` for the action plan and the installed skills for the rules.'
  }

  const parts: string[] = [doctrine.trim()]

  if (mode === 'doctrine-plus-skills') {
    const skillBodies: string[] = []
    for (const name of skillsFor(integration)) {
      const body = readBundledSkill(name)
      if (body) {
        skillBodies.push(`---\n\n# Skill: ${name}\n\n${stripFrontmatter(body)}`)
      }
    }
    if (skillBodies.length > 0) {
      parts.push(
        '',
        '## Skill references',
        '',
        'These are the CipherStash skills that apply to this project. They contain the API details and patterns the rules above reference.',
        '',
        skillBodies.join('\n\n'),
      )
    }
  }

  return parts.join('\n')
}

/**
 * Strip a leading YAML frontmatter block (`---\n...---\n`) from a SKILL.md
 * body. Skill files use frontmatter for the Claude/Codex skill registry;
 * once we inline the content into AGENTS.md it just adds noise, since the
 * `# Skill: <name>` heading we emit already labels each section.
 */
function stripFrontmatter(body: string): string {
  if (!body.startsWith('---')) return body.trim()
  const end = body.indexOf('\n---', 3)
  if (end === -1) return body.trim()
  return body.slice(end + 4).trim()
}

function readDoctrine(): string | undefined {
  const dir = findBundledDir('doctrine')
  if (!dir) return undefined
  const file = join(dir, 'AGENTS-doctrine.md')
  return existsSync(file) ? readFileSync(file, 'utf-8') : undefined
}
