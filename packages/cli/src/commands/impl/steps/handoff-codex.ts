import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { buildAgentsMdBody } from '../../init/lib/build-agents-md.js'
import { spawnAgent, writeArtifacts } from '../../init/lib/handoff-helpers.js'
import {
  availableSkills,
  installSkills,
} from '../../init/lib/install-skills.js'
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
 *
 * ## When `.codex/` is not writable
 *
 * Codex sandboxes deny writes under `.codex/`, and the user cannot fix that
 * from here. Rather than hand Codex a project with no guidance, the skill
 * bodies are inlined into AGENTS.md — which lives at the project root and is
 * writable — using the same `doctrine-plus-skills` path the editor-agent
 * handoff uses for Cursor / Windsurf / Cline.
 *
 * This is why `installSkills` must never throw: it runs FIRST, so an
 * exception there used to abort the whole step, taking AGENTS.md and
 * `.cipherstash/` down with it. All five Codex runs of the rc.3 skilltester
 * matrix landed here (#736).
 */
export const handoffCodexStep: HandoffStep = {
  id: 'handoff-codex',
  name: 'Hand off to Codex',
  async run(state: InitState): Promise<InitState> {
    const cwd = process.cwd()
    const integration = state.integration ?? 'postgresql'

    const installed = installSkills(cwd, CODEX_SKILLS_DIR, integration)

    // Codex sandboxes deny writes under `.codex/`, so the skills copy can fail
    // for reasons the user cannot fix (#736 — it took out all five Codex runs
    // of the rc.3 matrix). AGENTS.md is written to the project root, which is
    // writable, so fall back to inlining the skill bodies there: Codex still
    // gets the API guidance, just in one file instead of a directory.
    //
    // Only when there were skills to install in the first place — a stripped
    // build has nothing to inline, and saying otherwise would be a false claim.
    const inlinable = installed.length === 0 ? availableSkills(integration) : []
    const useInlineFallback = inlinable.length > 0

    if (installed.length > 0) {
      p.log.success(
        `Installed ${installed.length} skill${installed.length !== 1 ? 's' : ''} into ${CODEX_SKILLS_DIR}/: ${installed.join(', ')}`,
      )
    } else if (useInlineFallback) {
      p.log.warn(
        `Could not write ${CODEX_SKILLS_DIR}/ — inlining ${inlinable.length} skill${inlinable.length !== 1 ? 's' : ''} into ${AGENTS_MD_REL_PATH} instead: ${inlinable.join(', ')}`,
      )
    }

    const agentsMdAbs = resolve(cwd, AGENTS_MD_REL_PATH)
    const managed = buildAgentsMdBody(
      integration,
      useInlineFallback ? 'doctrine-plus-skills' : 'doctrine-only',
    )
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
    // Point Codex at wherever the guidance actually ended up: the skills
    // directory when it was written, AGENTS.md when it was inlined instead,
    // and neither when this build ships no skills at all (claiming otherwise
    // sends the agent to read files that do not exist). The durable rules are
    // in AGENTS.md in every case, so the prompt stays useful regardless.
    const skillsClause =
      installed.length > 0
        ? `the skills under ${CODEX_SKILLS_DIR}/ have the API details; `
        : useInlineFallback
          ? `the skill references inlined in ${AGENTS_MD_REL_PATH} have the API details; `
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
