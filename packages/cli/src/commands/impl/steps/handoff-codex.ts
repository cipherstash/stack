import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { buildAgentsMdBody } from '../../init/lib/build-agents-md.js'
import { spawnAgent, writeArtifacts } from '../../init/lib/handoff-helpers.js'
import { installSkills } from '../../init/lib/install-skills.js'
import { upsertManagedBlock } from '../../init/lib/sentinel-upsert.js'
import {
  CONTEXT_REL_PATH,
  SETUP_PROMPT_REL_PATH,
} from '../../init/lib/write-context.js'
import type { HandoffStep, InitState } from '../../init/types.js'

const AGENTS_MD_REL_PATH = 'AGENTS.md'
const CODEX_SKILLS_DIR = '.codex/skills'

const CODEX_INSTALL_URL = 'https://github.com/openai/codex'

/**
 * Hand off to Codex CLI. Following OpenAI's Codex guidance, AGENTS.md
 * holds durable doctrine ("never log plaintext", "encrypted columns are
 * jsonb null", three-phase migration etc.) while the procedural skills
 * live in `.codex/skills/`. Both are written here.
 *
 * AGENTS.md is sentinel-upserted so re-runs replace only our region and
 * any user content outside it survives.
 */
export const handoffCodexStep: HandoffStep = {
  id: 'handoff-codex',
  name: 'Hand off to Codex',
  async run(state: InitState): Promise<InitState> {
    const cwd = process.cwd()
    const integration = state.integration ?? 'postgresql'

    const installed = installSkills(cwd, CODEX_SKILLS_DIR, integration)
    if (installed.length > 0) {
      p.log.success(
        `Installed ${installed.length} skill${installed.length !== 1 ? 's' : ''} into ${CODEX_SKILLS_DIR}/: ${installed.join(', ')}`,
      )
    }

    const agentsMdAbs = resolve(cwd, AGENTS_MD_REL_PATH)
    const managed = buildAgentsMdBody(integration, 'doctrine-only')
    const existing = existsSync(agentsMdAbs)
      ? readFileSync(agentsMdAbs, 'utf-8')
      : undefined
    writeFileSync(
      agentsMdAbs,
      upsertManagedBlock({ existing, managed }),
      'utf-8',
    )
    p.log.success(`Wrote ${AGENTS_MD_REL_PATH}`)

    writeArtifacts(cwd, state, 'codex', installed)

    const mode = state.mode ?? 'implement'
    // Only reference the skills dir when skills were actually copied (a
    // stripped build returns []); the durable rules live in AGENTS.md either
    // way, so the prompt stays useful without them.
    const skillsClause =
      installed.length > 0
        ? `the skills under ${CODEX_SKILLS_DIR}/ have the API details; `
        : ''
    const launchPrompt =
      mode === 'plan'
        ? `Read ${SETUP_PROMPT_REL_PATH} and produce the planning deliverable it describes. AGENTS.md has the durable rules; ${skillsClause}${CONTEXT_REL_PATH} has the project facts. Do not edit code or run mutating commands during this phase.`
        : `Read ${SETUP_PROMPT_REL_PATH} and complete the setup steps. AGENTS.md has the durable rules; ${skillsClause}${CONTEXT_REL_PATH} has the project facts.`

    if (!state.agents?.cli.codex) {
      p.note(
        [
          'Codex is not installed on this machine.',
          `Install: ${CODEX_INSTALL_URL}`,
          '',
          'Once installed, run:',
          `  codex '${launchPrompt}'`,
        ].join('\n'),
        'Files written — install Codex to run the handoff',
      )
      return state
    }

    p.log.info('Launching Codex...')
    const exitCode = await spawnAgent('codex', launchPrompt)
    if (exitCode !== 0) {
      p.log.warn(
        `Codex exited with code ${exitCode}. Re-run \`codex '${launchPrompt}'\` to resume.`,
      )
    }

    return state
  },
}
