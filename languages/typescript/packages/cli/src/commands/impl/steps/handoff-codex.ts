import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { buildAgentsMdBody } from '../../init/lib/build-agents-md.js'
import {
  AGENTS_MD_REL_PATH,
  spawnAgent,
  writeAgentsMd,
  writeArtifacts,
} from '../../init/lib/handoff-helpers.js'
import { installSkills } from '../../init/lib/install-skills.js'
import {
  CONTEXT_REL_PATH,
  SETUP_PROMPT_REL_PATH,
} from '../../init/lib/write-context.js'
import type { HandoffStep, InitState } from '../../init/types.js'

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
 *
 * ## When `.codex/` is not writable
 *
 * Codex sandboxes deny writes under `.codex/`, and the user cannot fix that
 * from here. Rather than hand Codex a project with no guidance, any skill
 * that could not be copied has its body inlined into AGENTS.md — which
 * lives at the project root and is writable — using the same
 * `doctrine-plus-skills` path the editor-agent handoff uses for Cursor /
 * Windsurf / Cline. A partial copy inlines exactly the skills that failed.
 *
 * This is why `installSkills` must never throw: it runs FIRST, so an
 * exception there used to abort the whole step, taking AGENTS.md and
 * `.cipherstash/` down with it. All five Codex runs of the rc.3 skilltester
 * matrix landed here (#736). The AGENTS.md write itself is guarded for the
 * same reason (`writeAgentsMd`).
 */
export const handoffCodexStep: HandoffStep = {
  id: 'handoff-codex',
  name: 'Hand off to Codex',
  async run(state: InitState): Promise<InitState> {
    const cwd = process.cwd()
    const integration = state.integration ?? 'postgresql'

    const { copied, failed } = installSkills(cwd, CODEX_SKILLS_DIR, integration)

    if (copied.length > 0) {
      p.log.success(
        `Installed ${copied.length} skill${copied.length !== 1 ? 's' : ''} into ${CODEX_SKILLS_DIR}/: ${copied.join(', ')}`,
      )
    }
    if (failed.length > 0) {
      // installSkills already warned with the underlying error per failure;
      // this line announces the recovery, not the cause.
      p.log.warn(
        `Inlining ${failed.length} skill${failed.length !== 1 ? 's' : ''} that could not be installed to ${CODEX_SKILLS_DIR}/ into ${AGENTS_MD_REL_PATH} instead: ${failed.join(', ')}`,
      )
      if (copied.length === 0 && existsSync(resolve(cwd, CODEX_SKILLS_DIR))) {
        p.log.warn(
          `${CODEX_SKILLS_DIR}/ already exists from an earlier run and could not be refreshed — its contents may be stale; the inlined copies in ${AGENTS_MD_REL_PATH} are current.`,
        )
      }
    }

    const managed = buildAgentsMdBody(
      integration,
      failed.length > 0 ? 'doctrine-plus-skills' : 'doctrine-only',
      failed,
    )
    const agentsMdWritten = writeAgentsMd(cwd, managed)
    // Skills are only "inlined" if AGENTS.md actually landed — otherwise
    // they were delivered nowhere and the artifacts must say so.
    const inlined = agentsMdWritten ? failed : []
    const undelivered = agentsMdWritten ? [] : failed

    writeArtifacts(cwd, state, 'codex', {
      installed: copied,
      inlined,
      failed: undelivered,
    })

    const mode = state.mode ?? 'implement'
    // Point Codex at wherever the guidance actually ended up: the skills
    // directory, AGENTS.md, both after a partial copy, and neither when this
    // build ships no skills at all (claiming otherwise sends the agent to
    // read files that do not exist). The durable rules are in AGENTS.md in
    // every case, so the prompt stays useful regardless.
    const skillLocations = [
      ...(copied.length > 0 ? [`the skills under ${CODEX_SKILLS_DIR}/`] : []),
      ...(inlined.length > 0
        ? [`the skill references inlined in ${AGENTS_MD_REL_PATH}`]
        : []),
    ]
    const skillsClause =
      skillLocations.length > 0
        ? `${skillLocations.join(' and ')} have the API details; `
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

    return { ...state, agentLaunched: true }
  },
}
